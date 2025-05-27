<?php

namespace Database\Seeders;

use App\Models\OAuthClient;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

class OAuthClientSeeder extends Seeder
{
    public function run(): void
    {
        // Create a test client
        OAuthClient::create([
            'name' => 'Test Application',
            'client_id' => 'test_client_' . Str::random(32),
            'client_secret' => Str::random(40),
            'redirect_uri' => 'http://localhost:3000/callback',
            'is_confidential' => true,
        ]);
    }
}
