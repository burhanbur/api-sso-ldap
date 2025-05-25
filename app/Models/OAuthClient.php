<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class OAuthClient extends Model
{
    use HasUuids, SoftDeletes;

    protected $fillable = [
        'name',
        'client_id',
        'client_secret',
        'redirect_uri',
        'is_confidential',
    ];

    protected $casts = [
        'is_confidential' => 'boolean',
    ];

    public function accessTokens()
    {
        return $this->hasMany(OAuthAccessToken::class, 'client_id');
    }
}
