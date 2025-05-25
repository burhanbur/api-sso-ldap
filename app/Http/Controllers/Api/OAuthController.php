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
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

use App\Http\Resources\UserResource;
use App\Models\OAuthClient;
use App\Models\User;
use App\Traits\ApiResponse;
use App\Utilities\Ldap;
use App\Utilities\Utils;

use Exception;

class OAuthController extends Controller
{
    use ApiResponse;

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
            return $this->errorResponse($validator->errors(), 422);
        }

        $client = OAuthClient::where('client_id', $request->client_id)->first();
        
        if (!$client) {
            return $this->errorResponse('Invalid client_id', 401);
        }

        if ($client->redirect_uri !== $request->redirect_uri) {
            return $this->errorResponse('Invalid redirect_uri', 401);
        }

        // Store the OAuth request parameters in session
        Session::put('oauth_request', $request->all());

        // If user is not logged in, redirect to login page
        if (!Auth::check()) {
            return response()->json([
                'login_url' => URL::to('/oauth/login') . '?client_id=' . $client->client_id
            ]);
        }

        // Generate authorization code
        $code = Str::random(40);
        Redis::setex('oauth_code:' . $code, 600, json_encode([
            'client_id' => $client->id,
            'user_id' => Auth::id(),
            'scopes' => $request->scope ? explode(' ', $request->scope) : []
        ]));

        $query = http_build_query([
            'code' => $code,
            'state' => $request->state
        ]);

        return response()->json([
            'redirect_uri' => $request->redirect_uri . '?' . $query
        ]);
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
            return $this->errorResponse($validator->errors(), 422);
        }

        $client = OAuthClient::where('client_id', $request->client_id)
                           ->where('client_secret', $request->client_secret)
                           ->first();

        if (!$client) {
            return $this->errorResponse('Invalid client credentials', 401);
        }

        if ($request->grant_type === 'authorization_code') {
            $codeData = Redis::get('oauth_code:' . $request->code);
            
            if (!$codeData) {
                return $this->errorResponse('Invalid or expired code', 401);
            }

            $codeData = json_decode($codeData);
            Redis::del('oauth_code:' . $request->code);

            if ($codeData->client_id !== $client->id) {
                return $this->errorResponse('Code was not issued for this client', 401);
            }

            // Generate tokens
            $accessToken = Str::random(60);
            $refreshToken = Str::random(60);

            $token = new OAuthAccessToken([
                'user_id' => $codeData->user_id,
                'client_id' => $client->id,
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'expires_at' => now()->addHours(24),
                'scopes' => $codeData->scopes
            ]);

            $token->save();

        } else { // refresh_token grant
            $token = OAuthAccessToken::where('refresh_token', $request->refresh_token)
                                   ->where('client_id', $client->id)
                                   ->first();

            if (!$token) {
                return $this->errorResponse('Invalid refresh token', 401);
            }

            // Generate new access token
            $newAccessToken = Str::random(60);
            $token->update([
                'access_token' => $newAccessToken,
                'expires_at' => now()->addHours(24)
            ]);
        }

        return response()->json([
            'access_token' => $token->access_token,
            'token_type' => 'Bearer',
            'expires_in' => $token->expires_at->diffInSeconds(now()),
            'refresh_token' => $token->refresh_token,
            'scope' => implode(' ', $token->scopes ?? [])
        ]);
    }

    public function userinfo(Request $request)
    {
        $token = $request->bearerToken();
        
        if (!$token) {
            return $this->errorResponse('No token provided', 401);
        }

        $accessToken = OAuthAccessToken::where('access_token', $token)
                                     ->where('expires_at', '>', now())
                                     ->first();

        if (!$accessToken) {
            return $this->errorResponse('Invalid or expired token', 401);
        }

        $user = $accessToken->user;
        
        return new UserResource($user);
    }
}