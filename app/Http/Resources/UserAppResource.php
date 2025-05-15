<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Collection;

class UserAppResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'uuid' => $this->uuid,
            'code' => $this->code,
            'username' => $this->username,
            'full_name' => $this->full_name,
            'role' => $this->role,
            'assigned_by' => $this->assigned_by,
            'assigned_at' => $this->assigned_at,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at
        ];
    }
}