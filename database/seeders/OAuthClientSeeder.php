<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\OAuthClient;
use Illuminate\Support\Str;

class OAuthClientSeeder extends Seeder
{
    public function run(): void
    {
        // Create OAuth client for web-sso-ldap
        OAuthClient::create([
            'name' => 'Web SSO LDAP',
            'client_id' => Str::random(32),
            'client_secret' => Str::random(40),
            'redirect_uri' => 'http://localhost:5173/oauth/callback',
            'is_confidential' => true,
        ]);
    }
}
