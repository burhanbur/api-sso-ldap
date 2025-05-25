<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use App\Models\OAuthClient;
use Illuminate\Support\Str;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

Artisan::command('oauth:client:create {name} {redirect_uri}', function () {
    $client = OAuthClient::create([
        'name' => $this->argument('name'),
        'client_id' => Str::random(32),
        'client_secret' => Str::random(40),
        'redirect_uri' => $this->argument('redirect_uri'),
        'is_confidential' => true,
    ]);

    $this->info('OAuth client created successfully!');
    $this->table(
        ['Name', 'Client ID', 'Client Secret', 'Redirect URI'],
        [[$client->name, $client->client_id, $client->client_secret, $client->redirect_uri]]
    );
})->purpose('Create a new OAuth client');
