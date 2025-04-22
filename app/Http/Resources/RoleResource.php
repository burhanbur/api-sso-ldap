<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use App\Http\Resources\RoleTypeResource;
use App\Http\Resources\ScopeResource;

class RoleResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'uuid' => $this->uuid,
            'name' => $this->name,
            'display_name' => $this->display_name,
            'description' => $this->description,
            'role_type' => $this->whenLoaded('roleType', function() {
                return new RoleTypeResource($this->roleType);
            }),
            'scope_type' => $this->whenLoaded('scopeType', function() {
                return new ScopeResource($this->scopeType);
            }),
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at
        ];
    }
}
