<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

use App\Models\User;
use App\Http\Resources\UserResource;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Utilities\Ldap;
use App\Traits\ApiResponse;

use Exception;

class AuthController extends Controller
{
    use ApiResponse;

    public function login(Request $request)
    {
        $credentials = $request->only('username', 'password');

        if (!Ldap::bind($credentials['username'], $credentials['password'])) {
            return $this->errorResponse('Invalid LDAP credentials', 401);
        }

        $user = User::where('username', $credentials['username'])->first();

        if (!$user) {
            return $this->errorResponse('User not registered in Database local', 401);
        }

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => JWTAuth::factory()->getTTL() * 60
        ]);
    }

    public function logout(Request $request)
    {
        try {
            $user = auth()->user();
            $user->token()->revoke();

            return $this->successResponse(
                null,
                'User logged out successfully'
            );
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    public function forgotPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|exists:users,email',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            $user = User::where('email', $request->email)->first();

            if (!$user) {
                return $this->errorResponse('User not found', 404);
            }

            // Generate unique token
            $token = Str::random(64);
            
            // Store reset token
            DB::table('password_reset_tokens')->updateOrInsert(
                ['email' => $request->email],
                [
                    'token' => $token,
                    'created_at' => Carbon::now()
                ]
            );

            // Send reset email
            Mail::send('emails.reset-password', [
                'full_name' => $user->full_name,
                'email' => $user->email,
                'token' => $token,
                'username' => $user->username
            ], function($message) use ($request) {
                $message->to($request->email);
                $message->subject('Reset Password Notification');
            });

            return $this->successResponse(
                null,
                'Password reset link has been sent to your email'
            );
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    public function resetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'token' => 'required',
            'email' => 'required|email|exists:users,email',
            'password' => 'required|min:8',
            'password_confirmation' => 'required|same:password'
        ]);
    
        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }
    
        try {
            // Verify token
            $resetToken = DB::table('password_reset_tokens')
                ->where('email', $request->email)
                ->where('token', $request->token)
                ->first();
    
            if (!$resetToken) {
                return $this->errorResponse('Invalid reset token', 400);
            }
    
            // Check if token is expired (1 hour)
            if (Carbon::parse($resetToken->created_at)->addHour()->isPast()) {
                DB::table('password_reset_tokens')->where('email', $request->email)->delete();
                return $this->errorResponse('Reset token has expired', 400);
            }
    
            $user = User::where('email', $request->email)->first();
    
            // Update LDAP password
            $ldapConn = Ldap::connectToLdap();

            if (!$ldapConn) {
                throw new Exception('LDAP admin bind failed');
            }
    
            // Update password in LDAP
            $userDn = "uid={$user->username}," . env('LDAP_PEOPLE_OU') . "," . env('LDAP_BASE_DN');
            $newPassword = Ldap::hashLdapPassword($request->password);
            
            if (!@ldap_modify($ldapConn, $userDn, ['userPassword' => $newPassword])) {
                throw new Exception('Failed to update LDAP password');
            }
    
            // Delete used token
            DB::table('password_reset_tokens')->where('email', $request->email)->delete();
    
            return $this->successResponse(
                null,
                'Password has been reset successfully'
            );
    
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        } finally {
            if (isset($ldapConn)) {
                ldap_unbind($ldapConn);
            }
        }
    }

    public function changeMyPassword(Request $request)
    {
        $response = $this->errorResponse($this->errMessage);

        $validator = Validator::make($request->all(), [
            'current_password' => 'required',
            'new_password' => 'required|min:8',
            'new_password_confirmation' => 'required|min:8|same:new_password',
        ], [
            'new_password.min' => 'Password must be at least 8 characters',
            'new_password_confirmation.same' => 'Password confirmation does not match',
        ]);
        
        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $user = auth()->user();
            $user->password = bcrypt($request->new_password);
            $user->save();

            $username = $user->username;
            $userDn = "uid={$username}," . env('LDAP_PEOPLE_OU') . "," . env('LDAP_BASE_DN');

            $ldapConn = ldap_connect(env('LDAP_HOST'));
            ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);

            // Bind pakai password lama (validasi)
            if (!@ldap_bind($ldapConn, $userDn, $request->current_password)) {
                return $this->errorResponse('Invalid current password', 403);
            }

            // Format SSHA baru
            $newPass = Ldap::hashLdapPassword($request->new_password);

            // Ganti password di LDAP
            $entry = ['userPassword' => $newPass];

            if (!@ldap_modify($ldapConn, $userDn, $entry)) {
                throw new Exception('Failed to update password');
            }

            DB::commit();

            $response = $this->successResponse(
                new UserResource(auth()->user()),
                'Password updated successfully'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    public function changeUserPassword(Request $request)
    {
        $response = $this->errorResponse($this->errMessage);

        $validator = Validator::make($request->all(), [
            'username' => 'required|exists:users,username',
            'password' => 'required|min:8',
            'password_confirmation' => 'required|min:8|same:password',
        ], [
            'username.exists' => 'User not found',
            'password.required' => 'New password is required',
            'password.min' => 'Password must be at least 8 characters',
            'password_confirmation.required' => 'Password confirmation is required',
            'password_confirmation.same' => 'Password confirmation does not match',
        ]);
        
        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $ldapConn = Ldap::connectToLdap();

            if (!$ldapConn) {
                throw new Exception('LDAP admin bind failed');
            }

            $user = User::where('username', $request->username)->first();
            $user->password = bcrypt($request->password);
            $user->save();

            $username = $user->username;
            $userDn = "uid={$username}," . env('LDAP_PEOPLE_OU') . "," . env('LDAP_BASE_DN');
            $newPassword = Ldap::hashLdapPassword($request->password);
            $entry = ['userPassword' => $newPassword];

            if (!@ldap_modify($ldapConn, $userDn, $entry)) {
                throw new Exception('Failed to update LDAP password');
            }

            DB::commit();

            $response = $this->successResponse(
                new UserResource(auth()->user()),
                'Password updated successfully'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    public function me()
    {
        $user = auth()->user();

        $roles = $user->userRoles()
            ->with(['role', 'application', 'entityType'])
            ->get()
            ->map(function ($userRole) {
                return [
                    'role_code' => $userRole->role->name ?? null,
                    'role_name' => $userRole->role->display_name ?? null,
                    'app_code' => $userRole->application->code ?? null,
                    'app_name' => $userRole->application->name ?? null,
                    'entity_type' => $userRole->entityType->code ?? null,
                    'entity_id' => $userRole->entity_id,
                ];
            });

        $data = [
            'uuid' => $user->uuid,
            'username' => $user->username,
            'full_name' => $user->full_name,
            'email' => $user->email,
            'status' => $user->status,
            'roles' => $roles,
        ];

        return $this->successResponse(
            $data,
            'User data retrieved successfully'
        );
    }
}
