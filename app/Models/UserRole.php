<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class UserRole extends Model
{
    use HasFactory;

    protected $fillable = [
        'uuid', 'user_id', 'role_id', 'app_id', 'entity_type_id', 'entity_id', 'assigned_by', 'assigned_at', 'created_at', 'updated_at'
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function role()
    {
        return $this->belongsTo(Role::class);
    }

    public function application()
    {
        return $this->belongsTo(Application::class, 'app_id');
    }

    public function entityType()
    {
        return $this->belongsTo(EntityType::class, 'entity_type_id');
    }

    public function assigner()
    {
        return $this->belongsTo(User::class, 'assigned_by');
    }
}
