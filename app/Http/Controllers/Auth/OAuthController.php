<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Models\OAuthAccessToken;
use App\Models\OAuthClient;
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
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

class OAuthController extends Controller
{
    public function showLoginForm(Request $request)
    {
        $clientId = $request->query('client_id');
        $client = OAuthClient::where('client_id', $clientId)->first();
        $redirect_uri = $client->redirect_uri ?? '';

        return view('oauth.login');
    }

    public function login(Request $request)
    {
        $request->validate([
            'username' => 'required|string',
            'password' => 'required|string',
            'client_id' => 'required|string'
        ]);

        // Verify client
        $client = OAuthClient::where('client_id', $request->client_id)->first();

        if (!$client) {
            return redirect()->route('oauth.error', ['error' => 'invalid_client']);
        }

        // Get OAuth request from session
        $oauthRequest = session('oauth_request');
        if (!$oauthRequest) {
            return redirect()->route('oauth.error', ['error' => 'invalid_request']);
        }

        try {
            // Authenticate using LDAP
            $ldap = new Ldap();
            $bind = $ldap->bind($request->username, $request->password);
            
            if (!$bind) {
                throw new Exception('Invalid credentials');
            }

            $user = User::where('username', $request->username)->first();

            if ($user) {
                Auth::login($user);

                // Redirect back to authorization endpoint
                return redirect()->route('oauth.authorize', $oauthRequest);
            }
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
            return redirect()->route('oauth.error', [
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first()
            ]);
        }

        // Verify client
        $client = OAuthClient::where('client_id', $request->client_id)->first();
        if (!$client) {
            return redirect()->route('oauth.error', ['error' => 'invalid_client']);
        }

        // Verify redirect URI
        if ($client->redirect_uri !== $request->redirect_uri) {
            return redirect()->route('oauth.error', ['error' => 'invalid_redirect_uri']);
        }

        // Store OAuth request in session
        session(['oauth_request' => $request->all()]);

        // If user is not logged in, redirect to login
        if (!Auth::check()) {
            return redirect()->route('oauth.login', ['client_id' => $request->client_id]);
        }

        // Generate authorization code
        $code = Str::random(40);
        
        // Store the code in Redis with short expiration (10 minutes)
        Redis::setex("oauth:code:$code", 600, json_encode([
            'client_id' => $client->id,
            'user_id' => Auth::id(),
            'scopes' => $request->scope ? explode(' ', $request->scope) : []
        ]));

        // Redirect back to client with code
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
        $client = OAuthClient::where('client_id', $request->client_id)
                           ->where('client_secret', $request->client_secret)
                           ->first();

        if (!$client) {
            return response()->json([
                'error' => 'invalid_client'
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

            return response()->json([
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'Bearer',
                'expires_in' => 86400
            ]);
        } else {
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
