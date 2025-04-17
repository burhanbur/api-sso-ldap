<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Role extends Model
{
    use HasFactory;

    protected $fillable = [
        'uuid', 'name', 'display_name', 'description',
        'role_type_id', 'scope_type_id'
    ];

    public function roleType()
    {
        return $this->belongsTo(RoleType::class);
    }

    public function scopeType()
    {
        return $this->belongsTo(Scope::class, 'scope_type_id');
    }

    public function userRoles()
    {
        return $this->hasMany(UserRole::class);
    }

    public function users()
    {
        return $this->belongsToMany(User::class, 'user_roles')
            ->withPivot('app_id', 'entity_type_id', 'entity_id', 'assigned_by', 'assigned_at')
            ->withTimestamps();
    }
}
