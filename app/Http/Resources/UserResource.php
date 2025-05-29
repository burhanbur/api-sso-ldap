<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'uuid' => $this->uuid,
            'username' => $this->username,
            'code' => $this->code,
            'full_name' => $this->full_name,
            'nickname' => $this->nickname,
            'email' => $this->email,
            'alt_email' => $this->alt_email,
            'join_date' => $this->join_date,
            'title' => $this->title,
            'status' => $this->status,
            'is_impersonated' => $this->when($this->is_impersonated, true),
            'impersonated_by' => $this->when($this->impersonated_by, $this->impersonated_by),
            'app_access' => $this->whenLoaded('userRoles', function () {
                return $this->userRoles
                    ->groupBy(fn ($role) => $role->application->code ?? 'unknown')
                    ->map(function ($roles) {
                        $first = $roles->first();
        
                        return [
                            'uuid' => $first->application->uuid ?? null,
                            'code' => $first->application->code ?? null,
                            'name' => $first->application->name ?? null,
                            'base_url'  => $first->application->base_url ?? null,
                            'roles' => $roles->map(function ($role) {
                                return [
                                    'uuid' => $role->role->uuid ?? null,
                                    'code' => $role->role->name ?? null,
                                    'name' => $role->role->display_name ?? null,
                                    'entity' => [
                                        'uuid' => $role->entityType->uuid ?? null,
                                        'type' => $role->entityType->code ?? null,
                                        'id' => $role->entity_id,
                                    ],
                                ];
                            })->values(),
                        ];
                    })->values();
            }),
        ];        
    }
}
