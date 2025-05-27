<?php

namespace App\Console\Commands;

use App\Models\OAuthClient;
use Illuminate\Console\Command;
use Illuminate\Support\Str;

class CreateOAuthClientCommand extends Command
{
    protected $signature = 'oauth:client
                          {name : The name of the client application}
                          {redirect_uri : The callback URL for the client}
                          {--confidential=true : Whether the client is confidential}';

    protected $description = 'Create a new OAuth client';

    public function handle()
    {
        $client = OAuthClient::create([
            'name' => $this->argument('name'),
            'client_id' => 'client_' . Str::random(32),
            'client_secret' => Str::random(40),
            'redirect_uri' => $this->argument('redirect_uri'),
            'is_confidential' => $this->option('confidential') === 'true',
        ]);

        $this->info('OAuth client created successfully!');
        $this->table(
            ['Name', 'Client ID', 'Client Secret', 'Redirect URI'],
            [[
                $client->name,
                $client->client_id,
                $client->client_secret,
                $client->redirect_uri,
            ]]
        );
    }
}
