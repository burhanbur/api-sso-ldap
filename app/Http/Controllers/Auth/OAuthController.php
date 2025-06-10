<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Models\OAuthAccessToken;
use App\Models\Application;
use App\Models\User;
use App\Utilities\Ldap;
use App\Utilities\Utils;

use Exception;
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
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

use Tymon\JWTAuth\Facades\JWTAuth;

class OAuthController extends Controller
{
    public function loginForm(Request $request)
    {
        $clientId = $request->query('client_id');
        $redirect_uri = $request->query('redirect_uri');
        $client = Application::where('client_id', $clientId)->first();
        
        $cookieAccessToken = @$_COOKIE[config('cookie.name')];
        if ($cookieAccessToken) {
            $params = [
                'client_id' => $request->query('client_id'),
                'redirect_uri' => $request->query('redirect_uri'),
                'response_type' => 'code',
                'scope' => $request->query('scope'),
            ];

            return redirect()->route('oauth.authorize', $params);
        }

        if (!$clientId || !$redirect_uri) {
            return Redirect::to(env('CENTRAL_AUTH_URL'));
        }

        return view('oauth.login');
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string',
            'password' => 'required|string',
            'client_id' => 'required|string'
        ]);

        if ($validator->fails()) {
            // return redirect()->route('oauth.error', [
            //     'error' => 'invalid_request', 
            //     'error_description' => $validator->errors()->first()
            // ]);
            
            return back()->withErrors(['error_description' => $validator->errors()->first()]);
        }

        // Verify client
        $client = Application::where('client_id', $request->client_id)->first();

        if (!$client) {
            return back()->withErrors(['client_id' => 'Client not found']);
        }

        try {
            // Authenticate using LDAP
            $ldap = new Ldap();
            $bind = $ldap->bind($request->username, $request->password);
            
            if (!$bind) {
                throw new Exception('Invalid credentials');
            }

            $user = User::where('username', $request->username)->where('status', 'Aktif')->first();

            if (!$user) {
                throw new Exception('User not found');
            }

            $token = JWTAuth::fromUser($user);

            Utils::getInstance()->storeTokenInRedis($user->uuid, $token);

            $oauthRequest = [
                'client_id' => $request->client_id,
                'redirect_uri' => $request->redirect_uri,
                'response_type' => 'code',
                'scope' => $request->scope,
                'state' => $request->state,
            ];

            $response = redirect()->route('oauth.authorize', $oauthRequest);
            $response->cookie(
                    config('cookie.name'), // nama cookie
                $token, // nilai token
                config('jwt.refresh_ttl'), // durasi dalam menit
                '/', // path
                config('cookie.domain'), // domain lintas subdomain (kalau dev atau prod ganti .universitaspertamina.ac.id)
                config('cookie.secure'), // secure (gunakan true (HTTPS) di produksi)
                true, // httpOnly (tidak bisa dibaca JS)
                false, // raw
                'Lax' // SameSite ('Strict', 'Lax' atau 'None')
            );

            return $response;
        } catch (Exception $e) {
            return back()->withErrors(['username' => 'Invalid credentials']);
        }

        return back()->withErrors(['username' => 'Invalid credentials']);
    }

    public function authorize(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'client_id' => 'required|string',
            'redirect_uri' => 'required|string|url',
            'response_type' => 'required|string|in:code',
            'scope' => 'nullable|string',
            'state' => 'nullable|string'
        ]);

        if ($validator->fails()) {
            // return redirect()->route('oauth.error', [
            //     'error' => 'invalid_request',
            //     'error_description' => $validator->errors()->first()
            // ]);
            return back()->withErrors(['error_description' => $validator->errors()->first()]);
        }

        // Verify client
        $client = Application::where('client_id', $request->client_id)->first();
        if (!$client) {
            // return redirect()->route('oauth.error', [
            //     'error' => 'invalid_client',
            //     'error_description' => 'Client not found'
            // ]);
            return back()->withErrors(['client_id' => 'Client not found']);
        }

        // TODO: ini harus dicek juga redirect_uri nya sama atau tidak dengan yang di database `applications`
        // Verify redirect URI
        // if ($client->redirect_uri !== $request->redirect_uri) {
        //     return redirect()->route('oauth.error', [
        //         'error' => 'invalid_redirect_uri',
        //         'error_description' => 'Redirect URI does not match'
        //     ]);
        // }

        $params = $validator->validated();

        $cookieAccessToken = @$_COOKIE[config('cookie.name')];

        if (!$cookieAccessToken) {
            return redirect()->route('oauth.login', $params);
        }

        JWTAuth::setToken($cookieAccessToken);
        $user = JWTAuth::authenticate();

        // Check if user is already authenticated
        if (!$user) {
            return redirect()->route('oauth.login', $params);
        }
        
        auth()->setUser($user);

        // Generate authorization code
        $code = Str::random(40);

        // Store the code in Redis with short expiration (10 minutes)
        Redis::setex("oauth:code:$code", 600, json_encode([
            'client_id' => $client->id,
            'user_id' => $user->id,
            'scopes' => $request->scope ? explode(' ', $request->scope) : []
        ]));

        // Redirect back to client with code and state
        $query = http_build_query([
            'code' => $code,
            'state' => $request->state
        ]);

        return redirect($request->redirect_uri . '?' . $query);
    }

    public function token(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'grant_type' => 'required|string|in:authorization_code,refresh_token',
            'client_id' => 'required|string',
            'client_secret' => 'required|string',
            'code' => 'required_if:grant_type,authorization_code|string',
            'refresh_token' => 'required_if:grant_type,refresh_token|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first()
            ], 400);
        }

        // Verify client credentials
        $client = Application::query()
            ->where('client_id', $request->client_id)
            ->where('client_secret', $request->client_secret)
            ->first();

        if (!$client) {
            return response()->json([
                'error' => 'invalid_client',
                'error_description' => 'Client not found'
            ], 401);
        }

        if ($request->grant_type === 'authorization_code') {
            // Get authorization code data from Redis
            $codeData = Redis::get("oauth:code:{$request->code}");
            if (!$codeData) {
                return response()->json([
                    'error' => 'invalid_grant',
                    'error_description' => 'Authorization code is invalid or expired'
                ], 400);
            }

            $codeData = json_decode($codeData);
            
            // Delete the used code
            Redis::del("oauth:code:{$request->code}");

            // Generate tokens
            $accessToken = Str::random(80);
            $refreshToken = Str::random(80);

            // Save access token
            OAuthAccessToken::create([
                'user_id' => $codeData->user_id,
                'client_id' => $client->id,
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'expires_at' => now()->addHours(24),
                'scopes' => $codeData->scopes
            ]);

            $user = User::find($codeData->user_id);

            return response()->json([
                'user' => $user,
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'Bearer',
                'expires_in' => 86400
            ]);
        } else {
            // NOTE: refresh_token belum dipakai
            // Refresh token flow
            $token = OAuthAccessToken::where('refresh_token', $request->refresh_token)
                ->where('client_id', $client->id)
                ->first();

            if (!$token) {
                return response()->json([
                    'error' => 'invalid_grant',
                    'error_description' => 'Refresh token is invalid'
                ], 400);
            }

            // Generate new tokens
            $newAccessToken = Str::random(80);
            $newRefreshToken = Str::random(80);

            // Update token
            $token->update([
                'access_token' => $newAccessToken,
                'refresh_token' => $newRefreshToken,
                'expires_at' => now()->addHours(24)
            ]);

            return response()->json([
                'access_token' => $newAccessToken,
                'refresh_token' => $newRefreshToken,
                'token_type' => 'Bearer',
                'expires_in' => 86400
            ]);
        }
    }

    public function userinfo(Request $request)
    {
        // Get user from OAuth token middleware
        $user = $request->oauth_user;

        return response()->json([
            'sub' => $user->uuid,
            'name' => $user->full_name,
            'nickname' => $user->nickname,
            'email' => $user->email,
            'email_verified' => true
        ]);
    }
}
