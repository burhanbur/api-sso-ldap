<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\OAuthClient;
use Illuminate\Support\Str;

class CreateOAuthClient extends Command
{
    protected $signature = 'oauth:client:create {name} {redirect_uri}';
    protected $description = 'Create a new OAuth client';

    public function handle()
    {
        $name = $this->argument('name');
        $redirectUri = $this->argument('redirect_uri');

        $client = OAuthClient::create([
            'name' => $name,
            'client_id' => Str::random(32),
            'client_secret' => Str::random(40),
            'redirect_uri' => $redirectUri,
            'is_confidential' => true,
        ]);

        $this->info('Client created successfully!');
        $this->table(
            ['Name', 'Client ID', 'Client Secret', 'Redirect URI'],
            [[$client->name, $client->client_id, $client->client_secret, $client->redirect_uri]]
        );
    }
}
