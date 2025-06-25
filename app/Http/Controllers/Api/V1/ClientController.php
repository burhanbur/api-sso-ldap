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
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\JWTException;

use Exception;

/**
 * @OA\Tag(
 *     name="Client Apps",
 *     description="API Endpoints Only for Client Apps management"
 * )
 */
class ClientController extends Controller
{
    use ApiResponse;

    /**
     * @OA\Get(
     *     path="/api/v1/client/callback",
     *     summary="Handle redirect to client apps callback redirect URL",
     *     tags={"Client Apps"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="app_id",
     *         in="query",
     *         description="ID aplikasi (UUID)",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Parameter(
     *         name="redirect_url",
     *         in="query",
     *         description="Client application callback URL",
     *         required=true,
     *         @OA\Schema(type="string", format="uri")
     *     ),
     *     @OA\Response(
     *         response=302,
     *         description="Redirects to the client application with token in query string",
     *         @OA\Header(
     *             header="Location",
     *             description="Redirect location",
     *             @OA\Schema(type="string", format="uri", example="https://client.app/callback?access_token=xxx")
     *         )
     *     ),
     * )
     */
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

            $token = @$_COOKIE[config('cookie.name')];

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

            $redirectTo = $redirectUrl . '?' . config('cookie.name') . '=' . $token;

            // Redirect to the client application with the token
            return Redirect::to($redirectTo);
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

    /**
     * @OA\Post(
     *     path="/api/v1/client/session",
     *     summary="Check session for client apps",
     *     tags={"Client Apps"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="x-app-id",
     *         in="header",
     *         description="ID aplikasi",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Success",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Token validation successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/client/check-session"),
     *             @OA\Property(property="method", type="string", example="POST"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="is_impersonation", type="boolean", example=true),
     *             @OA\Property(property="impersonated_by", type="string", example="53e4d3e1-0a4b-4e45-9d0c-8f1c4b2f1c2e"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="user", ref="#/components/schemas/UserResource"),
     *                 @OA\Property(property="access_token", type="string", example="Bearer eyJhbGciOiJIUz..."),
     *                 @OA\Property(property="token_type", type="string", example="bearer"),
     *                 @OA\Property(property="expires_in", type="integer", example=3600),
     *                 @OA\Property(property="formatted_expires_in", type="string", example="2023-06-01 10:00:00"),
     *                 @OA\Property(property="sso_session_valid", type="boolean", example=true),
     *                 @OA\Property(property="application_roles", type="object",
     *                     @OA\Property(property="role", type="object", 
     *                         @OA\Property(property="name", type="string", example="Admin"),
     *                         @OA\Property(property="display_name", type="string", example="Administrator"),
     *                     ),
     *                     @OA\Property(property="entity_type", type="object", 
     *                         @OA\Property(property="name", type="string", example="Application"),
     *                         @OA\Property(property="code", type="string", example="app"),
     *                     ),
     *                     @OA\Property(property="entity_id", type="string", example="testing-uuid"),
     *                 ),
     *             ),
     *         ),
     *     ),
     * )
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

            try {
                JWTAuth::setToken($tokenString);
                $user = JWTAuth::authenticate();
            } catch (TokenExpiredException $e) {
                // Token expired, coba refresh
                try {
                    $newToken = JWTAuth::refresh($tokenString);
                    JWTAuth::setToken($newToken);
                    $user = JWTAuth::authenticate();

                    // Update Redis: hapus token lama, simpan token baru
                    Utils::getInstance()->removeTokenFromRedis($user->uuid, $tokenString);
                    Utils::getInstance()->storeTokenInRedis($user->uuid, $newToken);

                    $tokenString = $newToken; // gunakan token baru untuk response
                } catch (JWTException $refreshException) {
                    return $this->errorResponse('Token telah kedaluwarsa dan tidak dapat diperbarui.', 401);
                }
            }

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

    /**
     * @OA\Post(
     *     path="/api/v1/client/session/clear",
     *     summary="Clear session",
     *     tags={"Client Apps"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Response(
     *         response=200,
     *         description="Sesi Anda telah berakhir.",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Sesi Anda telah berakhir."),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/client/session/clear"),
     *             @OA\Property(property="method", type="string", example="POST"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00")
     *         ),
     *     ),
     * )
     */
    public function clearSession(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            $token = JWTAuth::getToken();

            Utils::getInstance()->removeTokenFromRedis($user->uuid, $token->get());

            JWTAuth::invalidate($token);

            return $this->successResponse(
                null,
                'Sesi Anda telah berakhir.'
            )
            ->cookie(
                config('cookie.name'), // nama cookie
                '', // nilai kosong untuk menghapus cookie
                -1, // durasi negatif untuk menghapus cookie
                '/', // path
                config('cookie.domain'), // domain lintas subdomain (kalau dev atau prod ganti .universitaspertamina.ac.id)
                config('cookie.secure'), // secure (gunakan true (HTTPS) di produksi)
                true, // httpOnly (tidak bisa dibaca JS)
                false, // raw
                'Lax' // SameSite ('Strict', 'Lax' atau 'None')
            );
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    /**
     * @OA\Get(
     *     path="/api/v1/client/users/{code}/code",
     *     summary="Get user by code",
     *     tags={"Client Apps"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="code",
     *         in="path",
     *         description="User code",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Data pengguna berhasil didapatkan."),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/client/users/{code}/code"),
     *             @OA\Property(property="method", type="string", example="GET"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", ref="#/components/schemas/UserResource")
     *         )
     *     )
     * )
     */
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
    
    /**
     * @OA\Get(
     *     path="/api/v1/client/users/{uuid}/uuid",
     *     summary="Get user by uuid",
     *     tags={"Client Apps"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="User uuid",
     *         required=true,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Data pengguna berhasil didapatkan."),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/client/users/{uuid}/uuid"),
     *             @OA\Property(property="method", type="string", example="GET"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", ref="#/components/schemas/UserResource")
     *         )
     *     )
     * )
     */
    public function getUserByUuid(Request $request)
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
    
    /**
     * @OA\Post(
     *     path="/api/v1/client/users",
     *     summary="Insert or update user",
     *     tags={"Client Apps"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="x-app-id",
     *         in="header",
     *         description="ID aplikasi",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="code", type="string", example="NIP/NIM"),
     *             @OA\Property(property="email", type="string", example="johndoe@example.com"),
     *             @OA\Property(property="name", type="string", example="John Doe"),
     *             @OA\Property(property="type", type="string", example="staff"),
     *             @OA\Property(property="username", type="string", example="johndoe"),
     *             @OA\Property(property="password", type="string", example="12345678"),
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User inserted or updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Data pengguna berhasil disimpan."),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/client/users"),
     *             @OA\Property(property="method", type="string", example="POST"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", ref="#/components/schemas/UserResource")
     *         )
     *     )
     * )
     */
    public function insertOrUpdateUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'code' => 'required|string|max:255',
            'email' => 'required|email|max:255',
            'name' => 'required|string|max:255',
            'type' => 'required|string|max:255|in:student,staff',
            'username' => 'nullable|string|max:255',
            'password' => 'nullable|string|min:8',
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