<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Application extends Model
{
    use HasFactory;

    protected $fillable = [
        'uuid', 'code', 'name', 'alias', 'description', 'image',
        'is_active', 'base_url', 'login_url', 'platform_type', 'visibility', 'client_id', 'client_secret',
    ];

    public function userRoles()
    {
        return $this->hasMany(UserRole::class, 'app_id');
    }
}
