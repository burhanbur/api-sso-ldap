<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

use App\Models\Application;
use App\Models\User;
use App\Models\UserRole;
use App\Http\Resources\UserResource;
use App\Utilities\Ldap;
use App\Utilities\Utils;
use App\Traits\ApiResponse;

use Tymon\JWTAuth\Facades\JWTAuth;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

use Exception;

class ClientController extends Controller
{
    use ApiResponse;

    public function callback(Request $request)
    {
        try {
            $appId = $request->get('app_id');
            if (!$appId) {
                throw new Exception('ID aplikasi wajib diisi.', 400);
            }

            $redirectUrl = $request->get('redirect_url');
            if (!$redirectUrl) {
                throw new Exception('Redirect URL wajib diisi.', 400);
            }

            $application = Application::where('uuid', $appId)->where('is_active', true)->first();
            if (!$application) {
                throw new Exception('Aplikasi tidak ditemukan atau tidak aktif.', 400);
            }

            $token = @$_COOKIE['access_token'];

            if (!$token) {
                throw new Exception('Token tidak ditemukan. Silakan masuk melalui aplikasi utama terlebih dahulu.', 400);
            }

            // Validate the token
            JWTAuth::setToken($token);
            $user = JWTAuth::authenticate();
            
            if (!$user) {
                throw new Exception('Token tidak valid atau telah kedaluwarsa.', 401);
            }

            $now = now()->timestamp;
            
            // Check if token exists in Redis and is still valid
            $expiryTime = Redis::zscore("user_tokens:{$user->uuid}", $token);
            if (!$expiryTime || $expiryTime < $now) {
                throw new Exception('Token yang digunakan tidak berlaku atau sudah habis masa berlakunya.', 401);
            }

            // Check if user has access to the application
            $hasAccess = $user->userRoles()
                ->whereHas('application', function ($query) use ($appId) {
                    $query->where('uuid', $appId)->where('is_active', true);
                })
                ->exists();

            if (!$hasAccess) {
                throw new Exception('Pengguna tidak memiliki akses ke aplikasi ini.', 401);
            }

            // Redirect to the client application with the token
            return Redirect::to($redirectUrl . '?token_login=' . $token);
        } catch (Exception $ex) {
            Log::error('Error during SSO login: ' . $ex->getMessage());
            return Redirect::to(env('CENTRAL_AUTH_URL'));
        }
    }

    /**
     * Handle client application token after SSO login.
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
     * @request->header('x-app-id') string The application ID of the client application.
     * @request->header('Authorization') string The Bearer token for the authenticated user.
     * @return \Illuminate\Http\JsonResponse
     */
    public function checkSession(Request $request)
    {
        try {
            $appId = $request->header('x-app-id');
            if (!$appId) {
                return $this->errorResponse('ID aplikasi wajib diisi.', 400);
            }

            $tokenString = $request->bearerToken();
            if (!$tokenString) {
                return $this->errorResponse('Token wajib diisi.', 400);
            }
            
            // Validate token
            // $secret = config('jwt.secret');
            // $algo = config('jwt.algo');
            // $decoded = JWT::decode($tokenString, new Key($secret, $algo));
            // $user = User::find($decoded->sub);
            
            JWTAuth::setToken($tokenString);
            $user = JWTAuth::authenticate();

            // return response()->json([
            //     'secret_1' => $secret,
            //     // 'secret_2' => $secret2
            // ]);

            $now = now()->timestamp;
            // Check if token exists in Redis and is still valid
            $expiryTime = Redis::zscore("user_tokens:{$user->uuid}", $tokenString);
            if (!$expiryTime || $expiryTime < $now) {
                return $this->errorResponse('Token yang digunakan tidak berlaku atau sudah habis masa berlakunya.', 401);
            }

            // Load user relationships needed by client applications
            $user->load(['userRoles.role', 'userRoles.application', 'userRoles.entityType']);

            // Check if user has access to the requesting application
            $hasAccess = $user->userRoles()
                ->whereHas('application', function ($query) use ($appId) {
                    $query->where('uuid', $appId)
                          ->where('is_active', true);
                })
                ->exists();

            if (!$hasAccess) {
                return $this->errorResponse('Akses ke aplikasi ini tidak diizinkan untuk pengguna ini.', 403);
            }

            // Get user roles specific to this application
            $applicationRoles = $user->userRoles()
                ->with(['role', 'entityType'])
                ->whereHas('application', function ($query) use ($appId) {
                    $query->where('uuid', $appId);
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
            
            return $this->successResponse($response, 'Token validation successful');
        } catch (Exception $ex) {
            Log::error('Error during SSO validation: ' . $ex->getMessage());
            return $this->errorResponse('Token validation failed: ' . $ex->getMessage(), 500);
        }
    }

    public function getUserByCode(Request $request)
    {
        try {
            $code = $request->get('code');

            if (!$code) {
                return $this->errorResponse('NIP/NIM wajib diisi.', 400);
            }

            $user = User::where('code', $code)->first();

            if (!$user) {
                return $this->errorResponse('Data pengguna tidak ditemukan.', 404);
            }

            return $this->successResponse(
                new UserResource($user), 
                'User retrieved successfully'
            );
        } catch (Exception $e) {
            Log::error('Error retrieving user by code: ' . $e->getMessage());
            return $this->errorResponse('Terjadi kesalahan saat mengambil pengguna.', 500);
        }
    }    
    
    public function insertOrUpdateUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'code' => 'required|string|max:255',
            'name' => 'required|string|max:255',
            'type' => 'required|string|max:255|in:student,staff',
            'username' => 'nullable|string|max:255',
            'email' => 'required|email|max:255',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $appId = $request->header('x-app-id');

            // Find application by appId
            $application = Application::where('uuid', $appId)->first();
            if (!$application) {
                return $this->errorResponse('ID aplikasi wajib diisi.', 404);
            }

            // Find or create user
            $user = User::where('code', $request->code)->first();
            $isNewUser = !$user;

            $plainPassword = $request->password;
            $bcryptPassword = bcrypt($request->password);

            if ($isNewUser) {
                $user = new User();
                $user->uuid = Str::uuid();
                $user->code = $request->code;
                $user->password = $bcryptPassword;
                $user->created_by = auth()->user()->id;

                if ($request->username) {
                    $checkUsername = User::where('username', $request->username)->first();

                    if ($checkUsername) {
                        $username = Utils::getInstance()->generateUsername($request->name, $request->type);
                    } else {
                        $username = $request->username;
                    }
                } else {
                    $username = Utils::getInstance()->generateUsername($request->name, $request->type);
                }

                $user->username = $username;
                $user->full_name = $request->name;
                $user->nickname = $request->input('nickname', $request->name);
                $user->email = $request->email;
                $user->alt_email = $request->input('alt_email');
                $user->join_date = $request->input('join_date', now()->format('Y-m-d'));
                $user->title = $request->input('title');
                $user->status = $request->input('status', 'Aktif');
            }
            
            $user->save();

            // Prepare roles data
            $userRole = UserRole::where('user_id', $user->id)
                ->where('app_id', $application->id)
                ->first();
            
            if (!$userRole) {
                $userRole = new UserRole();
                $userRole->uuid = Str::uuid();
                $userRole->user_id = $user->id;
                $userRole->role_id = 2; // Defult role for user
                $userRole->app_id = $application->id;
                $userRole->entity_type_id = null;
                $userRole->entity_id = null;
                $userRole->assigned_by = auth()->user()->id;
                $userRole->assigned_at = now();
                $userRole->save();
            }

            // Sync with LDAP
            if ($isNewUser) {
                $sync = Ldap::syncUserFromLdap($user, 'store', $plainPassword);
            } else {
                $sync = Ldap::syncUserFromLdap($user, 'update');
            }

            if (!$sync) {
                DB::rollBack();
                return $this->errorResponse('Proses sinkronisasi pengguna ke LDAP tidak berhasil.', 500);
            }

            DB::commit();

            return $this->successResponse(
                new UserResource($user->load(['userRoles.role', 'userRoles.application', 'userRoles.entityType'])), 
                'Berhasil ' . ($isNewUser ? 'membuat' : 'mengubah') . ' data pengguna ' . $user->full_name . '.'
            );
        } catch (Exception $e) {
            DB::rollBack();
            Log::error('Error creating/updating user: ' . $e->getMessage());
            return $this->errorResponse('Terjadi kesalahan saat membuat atau memperbarui pengguna.', 500);
        }
    }

}