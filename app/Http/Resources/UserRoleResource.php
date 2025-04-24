<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Collection;

class UserRoleResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'uuid' => $this->uuid,
            'user' => $this->whenLoaded('user', function() {
                return [
                    'id' => $this->user->id,
                    'uuid' => $this->user->uuid,
                    'username' => $this->user->username,
                    'code' => $this->user->code,
                    'full_name' => $this->user->full_name,
                    'nickname' => $this->user->nickname,
                    'email' => $this->user->email,
                    'alt_email' => $this->user->alt_email,
                    'join_date' => $this->user->join_date,
                    'title' => $this->user->title,
                    'status' => $this->user->status,
                    'app_access' => Collection::make([$this->application])
                        ->groupBy('code')
                        ->map(function ($apps) {
                            $first = $apps->first();
                            return [
                                'code' => $first->code ?? null,
                                'name' => $first->name ?? null,
                                'base_url' => $first->base_url ?? null,
                                'roles' => Collection::make([$this->role])
                                    ->map(function ($role) {
                                        return [
                                            'code' => $role->name ?? null,
                                            'name' => $role->display_name ?? null,
                                            'entity' => [
                                                'type' => $this->whenLoaded('entityType', fn() => $this->entityType->code),
                                                'id' => $this->entity_id,
                                            ],
                                        ];
                                    })->values(),
                            ];
                        })->values(),
                ];
            }),
            'assigned_by' => new UserResource($this->whenLoaded('assigner')),
            'assigned_at' => $this->assigned_at,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at
        ];
    }
}