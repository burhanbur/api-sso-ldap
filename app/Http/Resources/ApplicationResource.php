<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ApplicationResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'uuid' => $this->uuid,
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'code' => $this->code,
            'name' => $this->name,
            'alias' => $this->alias,
            'description' => $this->description,
            'base_url' => $this->base_url,
            'login_url' => $this->login_url,
            'platform_type' => $this->platform_type,
            'visibility' => $this->visibility,
            'is_active' => $this->is_active,
            'image' => $this->image ? url($this->image) : null,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at
        ];
    }
}
