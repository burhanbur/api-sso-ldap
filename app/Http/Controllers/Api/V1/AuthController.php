<?php

namespace App\Http\Controllers\Api\V1;

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
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

use App\Http\Resources\UserResource;
use App\Models\User;
use App\Traits\ApiResponse;
use App\Utilities\Ldap;
use App\Utilities\Utils;

use Tymon\JWTAuth\Facades\JWTAuth;

use Exception;

class AuthController extends Controller
{
    use ApiResponse;

    /**
     * Handle a login request for the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        $credentials = $request->only('username', 'password');

        if (!Ldap::bind($credentials['username'], $credentials['password'])) {
            return $this->errorResponse('Username or password is incorrect', 401);
        }

        $user = User::where('username', $credentials['username'])->first();

        if (!$user) {
            return $this->errorResponse('User not registered', 401);
        }

        if ($user->status != 'Aktif') {
            return $this->errorResponse('Cannot login because user account status is inactive', 401);
        }

        $token = JWTAuth::fromUser($user);
        $expiredIn = JWTAuth::factory()->getTTL() * 60;

        Utils::getInstance()->storeTokenInRedis($user->uuid, $token);

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $expiredIn,
            'formatted_expires_in' => Carbon::now()->addMinutes(JWTAuth::factory()->getTTL())->format('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Invalidate the user's token and log out the user.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function logout(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            $token = JWTAuth::getToken();

            Utils::getInstance()->removeTokenFromRedis($user->uuid, $token->get());

            JWTAuth::invalidate($token);

            return $this->successResponse(
                null,
                'User logged out successfully'
            );
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    /**
     * Send a password reset link to the given email address
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
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
                'url' => env('VITE_APP_URL'),
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

    /**
     * Resets the user's password based on the given token
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
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

    /**
     * Change the current user's password
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
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

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
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

    /**
     * Refresh JWT token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refreshToken()
    {
        try {
            $oldToken = JWTAuth::getToken();
            $oldTokenString = $oldToken->get();
            $user = JWTAuth::parseToken()->authenticate();
            $newToken = JWTAuth::refresh($oldToken);
            $expiredIn = JWTAuth::factory()->getTTL() * 60;

            Utils::getInstance()->removeTokenFromRedis($user->uuid, $oldTokenString);
            Utils::getInstance()->storeTokenInRedis($user->uuid, $newToken);
            
            return response()->json([
                'access_token' => $newToken,
                'token_type' => 'bearer',
                'expires_in' => $expiredIn,
                'formatted_expires_in' => Carbon::now()->addMinutes(JWTAuth::factory()->getTTL())->format('Y-m-d H:i:s'),
            ]);
        } catch (Exception $e) {
            return $this->errorResponse('Could not refresh token', 401);
        }
    }

    /**
     * Retrieve the authenticated user's data along with their roles, applications, and entity types.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        $user = auth()->user()->load(['userRoles.role', 'userRoles.application', 'userRoles.entityType']);

        return $this->successResponse(
            new UserResource($user),
            'User data retrieved successfully'
        );
    }

    /**
     * Start impersonating a user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $uuid
     * @return \Illuminate\Http\JsonResponse
     */
    public function startImpersonate(Request $request, $uuid)
    {
        $admin = auth()->user();
        $target = User::where('uuid', $uuid)->first();

        if (!$target) {
            return $this->errorResponse('User not found', 404);
        }

        if ($admin->uuid === $target->uuid) {
            return $this->errorResponse('Cannot impersonate yourself', 403);
        }

        $target->setCustomClaims(['impersonated_by' => $admin->uuid]);
        $token = JWTAuth::fromUser($target);
        $ttl = JWTAuth::factory()->getTTL() * 60;

        // Simpan detail token dengan informasi impersonasi
        Redis::setex("token_details:{$token}", $ttl, json_encode([
            'uuid' => $target->uuid,
            'created_at' => now()->timestamp,
            'impersonated_by' => $admin->uuid,
            'is_impersonation' => true
        ]));
        
        // Simpan mapping token ke user
        Redis::setex("token_to_user:{$token}", $ttl, $target->uuid);
        
        // Tambahkan token ke sorted set dengan score = timestamp expired
        $expiresAt = now()->addSeconds($ttl)->timestamp;
        Redis::zadd("user_tokens:{$target->uuid}", $expiresAt, $token);

        return $this->successResponse(
            [
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => $ttl,
                'formatted_expires_in' => Carbon::now()->addMinutes(JWTAuth::factory()->getTTL())->format('Y-m-d H:i:s'),
                'impersonated_user' => $target,
            ],
            'Impersonation successfully'
        );
    }

    /**
     * Leave impersonation.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function leaveImpersonate(Request $request)
    {
        $current = auth()->user();
        $originalAdminUuid = JWTAuth::getPayload()->get('impersonated_by');
        $token = JWTAuth::getToken()->get();

        if (!$originalAdminUuid) {
            return $this->errorResponse('Not impersonating any user', 403);
        }

        $admin = User::where('uuid', $originalAdminUuid)->first();
        
        if (!$admin) {
            return $this->errorResponse('User not found', 404);
        }

        Utils::getInstance()->removeTokenFromRedis($current->uuid, $token);
        JWTAuth::invalidate(JWTAuth::getToken());
        $adminToken = JWTAuth::fromUser($admin);
        Utils::getInstance()->storeTokenInRedis($admin->uuid, $adminToken);

        return $this->successResponse(
            [
                'access_token' => $adminToken,
                'token_type' => 'bearer',
                'expires_in' => JWTAuth::factory()->getTTL() * 60,
                'formatted_expires_in' => Carbon::now()->addMinutes(JWTAuth::factory()->getTTL())->format('Y-m-d H:i:s'),
                'impersonated_user' => $current,
                'original_user' => $admin,
            ],
            'Impersonation revoked successfully'
        );
    }

    /**
     * Check if the session is valid.
     *
     * This endpoint checks if the token in the Authorization header is valid and matches the one stored in Redis.
     * If the token is invalid or does not match the one in Redis, a 401 Unauthorized response is returned.
     * If the token is valid, a 200 OK response with the user's data is returned.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    /* public function checkSession()
    {
        try {
            $token = JWTAuth::getToken()->get();
            $user = JWTAuth::parseToken()->authenticate();
            $now = now()->timestamp;

            // Periksa token di sorted set dengan memastikan skornya masih valid
            $expiryTime = Redis::zscore("user_tokens:{$user->uuid}", $token);
            
            if (!$expiryTime || $expiryTime < $now) {
                // Token tidak ditemukan atau sudah expired
                return $this->errorResponse('Session invalid or expired', 401);
            }
            
            return $this->successResponse(
                new UserResource($user), 
                'Session check successful'
            );
        } catch (Exception $ex) {
            return $this->errorResponse('Session check failed: ' . $ex->getMessage(), 401);
        }
    } */

    /**
     * Log out the user from all devices except the current one.
     *
     * This method invalidates all tokens associated with the user except the current session token.
     * It retrieves all valid tokens associated with the user and invalidates each one by one.
     * Expired tokens are cleaned before the process.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function logoutUserAllDevices(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            $currentToken = JWTAuth::getToken()->get();
            
            // Bersihkan token yang sudah expired
            Utils::getInstance()->cleanExpiredTokens($user->uuid);
            
            // Ambil semua token user yang masih valid
            $now = now()->timestamp;
            $tokens = Redis::zrangebyscore("user_tokens:{$user->uuid}", $now, '+inf');
            
            // Invalidate semua token kecuali yang sedang digunakan
            foreach ($tokens as $token) {
                if ($token !== $currentToken) {
                    try {
                        JWTAuth::setToken($token)->invalidate();
                        Utils::getInstance()->removeTokenFromRedis($user->uuid, $token);
                    } catch (Exception $e) {
                        // Abaikan error jika token sudah tidak valid
                    }
                }
            }
            
            return $this->successResponse(
                null,
                'Logged out from all other devices successfully'
            );
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    /**
     * Retrieves all active sessions for the current user.
     *
     * This API retrieves all valid tokens associated with the user and decodes each token to get the creation and expiration timestamps.
     * It also checks if the token is an impersonation token and adds the admin user's name to the response.
     * The response will include the total number of active sessions and an array of sessions, each containing the token, creation and expiration timestamps,
     * and a flag indicating if the session is the current active session.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function getUserActiveDevices(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            $now = now()->timestamp;
            
            // Bersihkan token yang sudah expired
            Utils::getInstance()->cleanExpiredTokens($user->uuid);
            
            // Ambil hanya token yang masih valid
            $tokens = Redis::zrangebyscore("user_tokens:{$user->uuid}", $now, '+inf');
            
            $sessions = [];
            foreach ($tokens as $token) {
                $details = Redis::get("token_details:{$token}");
                if ($details) {
                    $details = json_decode($details, true);
                    $session = [
                        // 'token' => substr($token, 0, 10) . '...', // Hanya tampilkan sebagian token
                        'token' => $token,
                        'created_at' => Carbon::createFromTimestamp($details['created_at'])->format('Y-m-d H:i:s'),
                        'expires_at' => Carbon::createFromTimestamp(Redis::zscore("user_tokens:{$user->uuid}", $token))->format('Y-m-d H:i:s')
                    ];
                    
                    // Tambahkan info impersonasi jika ada
                    if (isset($details['is_impersonation']) && $details['is_impersonation']) {
                        $adminUser = User::where('uuid', $details['impersonated_by'])->first();
                        $session['is_impersonation'] = true;
                        $session['impersonated_by'] = $adminUser ? $adminUser->name : 'Unknown Admin';
                    }
                    
                    // Tandai sesi yang sedang aktif
                    $session['is_current'] = JWTAuth::getToken()->get() === $token;
                    
                    $sessions[] = $session;
                }
            }
            
            return $this->successResponse(
                [
                    'active_sessions' => count($sessions),
                    'sessions' => $sessions,
                ],
                'Active devices retrieved successfully'
            );
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    /**
     * Retrieves all active impersonation sessions initiated by the current admin.
     *
     * This method fetches all active user sessions from Redis and filters 
     * them to identify sessions that are impersonations initiated by the 
     * currently authenticated admin. It checks if tokens are still valid 
     * and retrieves the associated user details.
     *
     * The response includes the total number of active impersonations 
     * and an array of impersonation details, each containing user information,
     * session start and expiration timestamps.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */

    public function getActiveImpersonations(Request $request)
    {
        try {
            $admin = auth()->user();
            $now = now()->timestamp;
            
            // Ambil semua sesi user
            $allTokens = Redis::keys("token_details:*");
            $activeImpersonations = [];
            
            foreach ($allTokens as $tokenKey) {
                $details = Redis::get($tokenKey);
                if ($details) {
                    $details = json_decode($details, true);
                    
                    // Periksa apakah ini adalah sesi impersonasi yang dilakukan oleh admin ini
                    if (isset($details['is_impersonation']) && 
                        $details['is_impersonation'] &&
                        $details['impersonated_by'] === $admin->uuid) {
                        
                        // Ekstrak token dari key
                        $token = str_replace("token_details:", "", $tokenKey);
                        
                        // Periksa apakah token masih valid
                        $userUuid = $details['uuid'];
                        $expiryTime = Redis::zscore("user_tokens:{$userUuid}", $token);
                        
                        if ($expiryTime && $expiryTime > $now) {
                            $user = User::where('uuid', $userUuid)->first();
                            
                            if ($user) {
                                $activeImpersonations[] = [
                                    'user' => [
                                        'uuid' => $user->uuid,
                                        'name' => $user->name,
                                        'username' => $user->username
                                    ],
                                    'started_at' => Carbon::createFromTimestamp($details['created_at'])->format('Y-m-d H:i:s'),
                                    'expires_at' => Carbon::createFromTimestamp($expiryTime)->format('Y-m-d H:i:s')
                                ];
                            }
                        }
                    }
                }
            }
            
            return $this->successResponse(
                [
                    'active_impersonations' => count($activeImpersonations),
                    'impersonations' => $activeImpersonations
                ],
                'Active impersonations retrieved successfully'
            );
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }
    
    /**
     * Handle client application callback after SSO login.
     *
     * This API is called by client applications after the user has been redirected
     * to the SSO login page and has been authenticated. The API verifies the
     * token and returns the user information and application roles.
     *
     * This endpoint is used by the client application to validate the token and get the user information.
     * The token is validated by checking if it exists in Redis and matches the one stored in Redis.
     * If the token is invalid or does not match the one in Redis, a 401 Unauthorized response is returned.
     * If the token is valid, a 200 OK response with the user's data is returned.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function checkSession(Request $request)
    {
        try {
            $clientId = $request->header('x-api-key');
            if (!$clientId) {
                return $this->errorResponse('Application client ID is required', 400);
            }

            $token = JWTAuth::getToken();
            if (!$token) {
                return $this->errorResponse('Token is required', 400);
            }
            
            // Validate token
            JWTAuth::setToken($token);
            $user = JWTAuth::parseToken()->authenticate();
            $tokenString = $token->get();
            $now = now()->timestamp;
            
            // Check if token exists in Redis and is still valid
            $expiryTime = Redis::zscore("user_tokens:{$user->uuid}", $tokenString);
            if (!$expiryTime || $expiryTime < $now) {
                return $this->errorResponse('Invalid or expired token', 401);
            }

            // Load user relationships needed by client applications
            $user->load(['userRoles.role', 'userRoles.application', 'userRoles.entityType']);

            // Check if user has access to the requesting application
            $hasAccess = $user->userRoles()
                ->whereHas('application', function ($query) use ($clientId) {
                    $query->where('client_id', $clientId)
                          ->where('is_active', true);
                })
                ->exists();

            if (!$hasAccess) {
                return $this->errorResponse('User does not have access to this application', 403);
            }

            // Get user roles specific to this application
            $applicationRoles = $user->userRoles()
                ->with(['role', 'entityType'])
                ->whereHas('application', function ($query) use ($clientId) {
                    $query->where('code', $clientId);
                })
                ->get();
        
            // Get token details
            $details = Redis::get("token_details:{$tokenString}");
            $isImpersonation = false;
            $impersonatedBy = null;
            
            if ($details) {
                $details = json_decode($details, true);
                if (isset($details['is_impersonation']) && $details['is_impersonation']) {
                    $isImpersonation = true;
                    $adminUser = User::where('uuid', $details['impersonated_by'])->first();
                    $impersonatedBy = $adminUser ? $adminUser->name : 'Unknown Admin';
                }
            }
            
            // Return user information for the client application
            $response = [
                'user' => new UserResource($user),
                'access_token' => $tokenString,
                'token_type' => 'bearer',
                'expires_in' => ($expiryTime - $now),
                'formatted_expires_in' => Carbon::createFromTimestamp($expiryTime)->format('Y-m-d H:i:s'),
                'sso_session_valid' => true,
                'application_roles' => $applicationRoles->map(function ($userRole) {
                    return [
                        'role' => [
                            'name' => $userRole->role->name,
                            'display_name' => $userRole->role->display_name,
                        ],
                        'entity_type' => $userRole->entityType ? [
                            'name' => $userRole->entityType->name,
                            'code' => $userRole->entityType->code,
                        ] : null,
                        'entity_id' => $userRole->entity_id,
                    ];
                })
            ];
            
            if ($isImpersonation) {
                $response['is_impersonation'] = true;
                $response['impersonated_by'] = $impersonatedBy;
            }
            
            return $this->successResponse($response, 'Callback successful');
        } catch (Exception $e) {
            return $this->errorResponse('Callback failed: ' . $e->getMessage(), 500);
        }
    }
}