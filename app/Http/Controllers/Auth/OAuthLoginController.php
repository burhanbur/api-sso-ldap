<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\OAuthClient;
use App\Utilities\Ldap;

class OAuthLoginController extends Controller
{
    public function showLoginForm(Request $request)
    {
        $clientId = $request->query('client_id');
        $client = OAuthClient::where('client_id', $clientId)->firstOrFail();

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
        $client = OAuthClient::where('client_id', $request->client_id)->firstOrFail();

        // Get OAuth request from session
        $oauthRequest = session('oauth_request');
        if (!$oauthRequest) {
            return redirect()->route('oauth.error', ['error' => 'invalid_request']);
        }

        try {
            // Authenticate using LDAP
            $ldap = new Ldap();
            $user = $ldap->authenticate($request->username, $request->password);

            if ($user) {
                Auth::login($user);

                // Redirect back to authorization endpoint
                return redirect()->route('oauth.authorize', $oauthRequest);
            }
        } catch (\Exception $e) {
            return back()->withErrors(['username' => 'Invalid credentials']);
        }

        return back()->withErrors(['username' => 'Invalid credentials']);
    }
}
