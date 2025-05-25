<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class OAuthAccessToken extends Model
{
    use HasUuids;

    protected $fillable = [
        'user_id',
        'client_id',
        'access_token',
        'refresh_token',
        'expires_at',
        'scopes',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'scopes' => 'array',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function client()
    {
        return $this->belongsTo(OAuthClient::class, 'client_id');
    }
}
