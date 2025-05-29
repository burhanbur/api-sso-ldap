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

/**
 * @OA\Tag(
 *     name="Authentication",
 *     description="API Endpoints for authentication"
 * )
 */
class AuthController extends Controller
{
    use ApiResponse;

    /**
     * @OA\Post(
     *     path="/api/v1/auth/login",
     *     summary="Authenticate user and get token",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"username","password"},
     *             @OA\Property(property="username", type="string", example="john.doe"),
     *             @OA\Property(property="password", type="string", format="password", example="secret123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Login successful"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLC..."),
     *                 @OA\Property(property="token_type", type="string", example="bearer"),
     *                 @OA\Property(property="expires_in", type="integer", example=3600)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Invalid credentials")
     *         )
     *     )
     * )
     */
    public function login(Request $request)
    {
        $credentials = $request->only('username', 'password');

        if (!Ldap::bind($credentials['username'], $credentials['password'])) {
            return $this->errorResponse('Kombinasi username dan password tidak valid.', 401);
        }

        $user = User::where('username', $credentials['username'])->first();

        if (!$user) {
            return $this->errorResponse('Login gagal. Periksa kembali data Anda.', 401);
        }

        if ($user->status != 'Aktif') {
            return $this->errorResponse('Akun Anda saat ini tidak aktif. Silakan hubungi admin untuk lebih lanjut.', 401);
        }

        $token = JWTAuth::fromUser($user);
        $expiredIn = JWTAuth::factory()->getTTL() * 60;

        Utils::getInstance()->storeTokenInRedis($user->uuid, $token);

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $expiredIn,
            'formatted_expires_in' => Carbon::now()->addMinutes(JWTAuth::factory()->getTTL())->format('Y-m-d H:i:s'),
        ])
        ->cookie(
            'access_token', // nama cookie
            $token, // nilai token
            $expiredIn / 60, // durasi dalam menit
            '/', // path
            config('cookie.domain'), // domain lintas subdomain (kalau dev atau prod ganti .universitaspertamina.ac.id)
            config('cookie.secure'), // secure (gunakan true (HTTPS) di produksi)
            true, // httpOnly (tidak bisa dibaca JS)
            false, // raw
            'Lax' // SameSite ('Strict', 'Lax' atau 'None')
        );
    }

    /**
     * @OA\Post(
     *     path="/api/v1/auth/logout",
     *     summary="Logout user and invalidate token",
     *     tags={"Authentication"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Response(
     *         response=200,
     *         description="Logged out successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Logged out successfully")
     *         )
     *     )
     * )
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
                'Sesi Anda telah berakhir.'
            )
            ->cookie(
                'access_token', // nama cookie
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
     * @OA\Post(
     *     path="/api/v1/auth/forgot-password",
     *     summary="Send password reset link",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Password reset link sent",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Password reset link has been sent to your email")
     *         )
     *     )
     * )
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
                return $this->errorResponse('Email tidak terdaftar. Pastikan penulisan email benar.', 404);
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
                'url' => config('central.auth_url'),
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
                'Link reset password telah dikirim ke email Anda.'
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
                return $this->errorResponse('Link reset password tidak valid atau sudah kadaluarsa.', 400);
            }
    
            // Check if token is expired (1 hour)
            if (Carbon::parse($resetToken->created_at)->addHour()->isPast()) {
                DB::table('password_reset_tokens')->where('email', $request->email)->delete();
                return $this->errorResponse('Link reset password Anda sudah melewati batas waktu 1 jam. ', 400);
            }
    
            $user = User::where('email', $request->email)->first();
    
            // Update LDAP password
            $ldapConn = Ldap::connectToLdap();

            if (!$ldapConn) {
                throw new Exception('Gagal terhubung ke server direktori. Silakan cek kredensial admin LDAP atau konfigurasi server.');
            }
    
            // Update password in LDAP
            $userDn = "uid={$user->username}," . env('LDAP_PEOPLE_OU') . "," . env('LDAP_BASE_DN');
            $newPassword = Ldap::hashLdapPassword($request->password);
            
            if (!@ldap_modify($ldapConn, $userDn, ['userPassword' => $newPassword])) {
                throw new Exception('Gagal memperbarui password. Silakan coba lagi atau hubungi administrator sistem.');
            }
    
            // Delete used token
            DB::table('password_reset_tokens')->where('email', $request->email)->delete();
    
            return $this->successResponse(
                null,
                'Kata sandi telah berhasil direset. Silakan masuk dengan kata sandi baru Anda.'
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
                return $this->errorResponse('Password yang Anda masukkan tidak valid.', 403);
            }

            // Format SSHA baru
            $newPass = Ldap::hashLdapPassword($request->new_password);

            // Ganti password di LDAP
            $entry = ['userPassword' => $newPass];

            if (!@ldap_modify($ldapConn, $userDn, $entry)) {
                throw new Exception('Gagal memperbarui password. Silakan coba lagi atau hubungi administrator sistem.');
            }

            DB::commit();

            $response = $this->successResponse(
                new UserResource(auth()->user()),
                'Password berhasil diperbarui.'
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
                throw new Exception('Gagal terhubung ke server direktori. Silakan cek kredensial admin LDAP atau konfigurasi server.');
            }

            $user = User::where('username', $request->username)->first();
            $user->password = bcrypt($request->password);
            $user->save();

            $username = $user->username;
            $userDn = "uid={$username}," . env('LDAP_PEOPLE_OU') . "," . env('LDAP_BASE_DN');
            $newPassword = Ldap::hashLdapPassword($request->password);
            $entry = ['userPassword' => $newPassword];

            if (!@ldap_modify($ldapConn, $userDn, $entry)) {
                throw new Exception('Gagal memperbarui password. Silakan coba lagi atau hubungi administrator sistem.');
            }

            DB::commit();

            $response = $this->successResponse(
                new UserResource(auth()->user()),
                'Password berhasil diperbarui.'
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
            ])
            ->cookie(
                'access_token', // nama cookie
                $newToken, // nilai token
                $expiredIn / 60, // durasi dalam menit
                '/', // path
                config('cookie.domain'), // domain lintas subdomain (kalau dev atau prod ganti .universitaspertamina.ac.id)
                config('cookie.secure'), // secure (gunakan true (HTTPS) di produksi)
                true, // httpOnly (tidak bisa dibaca JS)
                false, // raw
                'Lax' // SameSite ('Strict', 'Lax' atau 'None')
            );
        } catch (Exception $ex) {
            return $this->errorResponse('Sesi Anda telah berakhir. Silakan login kembali.', 401);
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
            return $this->errorResponse('Data pengguna tidak ditemukan.', 404);
        }

        if ($admin->uuid === $target->uuid) {
            return $this->errorResponse('Tidak dapat impersonasi diri sendiri.', 403);
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
            'Berhasil impersonasi sebagai ' . $target->full_name . '.'
        )
        ->cookie(
            'access_token', // nama cookie
            $token, // nilai token
            $ttl / 60, // durasi dalam menit
            '/', // path
            config('cookie.domain'), // domain lintas subdomain (kalau dev atau prod ganti .universitaspertamina.ac.id)
            config('cookie.secure'), // secure (gunakan true (HTTPS) di produksi)
            true, // httpOnly (tidak bisa dibaca JS)
            false, // raw
            'Lax' // SameSite ('Strict', 'Lax' atau 'None')
        )
        ->cookie(
            'impersonated_by', // nama cookie
            $admin->uuid, // nilai token
            $ttl / 60, // durasi dalam menit
            '/', // path
            config('cookie.domain'), // domain lintas subdomain (kalau dev atau prod ganti .universitaspertamina.ac.id)
            config('cookie.secure'), // secure (gunakan true (HTTPS) di produksi)
            true, // httpOnly (tidak bisa dibaca JS)
            false, // raw
            'Lax' // SameSite ('Strict', 'Lax' atau 'None')
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
            return $this->errorResponse('Anda tidak sedang impersonasi pengguna lain.', 403);
        }

        $admin = User::where('uuid', $originalAdminUuid)->first();
        
        if (!$admin) {
            return $this->errorResponse('Data pengguna tidak ditemukan.', 404);
        }

        Utils::getInstance()->removeTokenFromRedis($current->uuid, $token);
        JWTAuth::invalidate(JWTAuth::getToken());
        $adminToken = JWTAuth::fromUser($admin);
        Utils::getInstance()->storeTokenInRedis($admin->uuid, $adminToken);
        $expiresIn = JWTAuth::factory()->getTTL() * 60;

        return $this->successResponse(
            [
                'access_token' => $adminToken,
                'token_type' => 'bearer',
                'expires_in' => $expiresIn,
                'formatted_expires_in' => Carbon::now()->addMinutes(JWTAuth::factory()->getTTL())->format('Y-m-d H:i:s'),
                'impersonated_user' => $current,
                'original_user' => $admin,
            ],
            'Berhasil mengakhiri impersonasi sebagai ' . $current->full_name . '.'
        )
        ->cookie(
            'access_token', // nama cookie
            $adminToken, // nilai token
            $expiresIn / 60, // durasi dalam menit
            '/', // path
            config('cookie.domain'), // domain lintas subdomain (kalau dev atau prod ganti .universitaspertamina.ac.id)
            config('cookie.secure'), // secure (gunakan true (HTTPS) di produksi)
            true, // httpOnly (tidak bisa dibaca JS)
            false, // raw
            'Lax' // SameSite ('Strict', 'Lax' atau 'None')

        )
        ->cookie(
            'impersonated_by', // nama cookie
            '', // nilai kosong untuk menghapus cookie
            -1, // durasi negatif untuk menghapus cookie
            '/', // path
            config('cookie.domain'), // domain lintas subdomain (kalau dev atau prod ganti .universitaspertamina.ac.id)
            config('cookie.secure'), // secure (gunakan true (HTTPS) di produksi)
            true, // httpOnly (tidak bisa dibaca JS)
            false, // raw
            'Lax' // SameSite ('Strict', 'Lax' atau 'None')
        );
    }

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
                'Berhasil keluar dari semua perangkat.'
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
}