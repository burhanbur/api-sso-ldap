<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class EntityType extends Model
{
    use HasFactory;

    protected $fillable = [
        'uuid', 'code', 'name', 'description'
    ];

    public function userRoles()
    {
        return $this->hasMany(UserRole::class, 'entity_type_id');
    }
}
