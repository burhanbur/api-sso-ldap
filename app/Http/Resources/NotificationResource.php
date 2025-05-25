<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class NotificationResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'uuid' => $this->uuid,
            'user_id' => $this->user_id,
            'app_id' => $this->app_id,
            'type' => $this->type,
            'subject' => $this->subject,
            'content' => $this->content,
            'detail_url' => $this->detail_url,
            'is_read' => $this->is_read,
            'read_at' => $this->read_at,
            'application' => $this->whenLoaded('application', function () {
                return [
                    'id' => $this->application->id,
                    'code' => $this->application->code,
                    'client_id' => $this->application->client_id,
                    'name' => $this->application->name,
                ];
            }),
            'user' => $this->whenLoaded('user', function () {
                return [
                    'id' => $this->user->id,
                    'username' => $this->user->username,
                    'full_name' => $this->user->full_name,
                    'code' => $this->user->code,
                    'email' => $this->user->email,
                ];
            }),
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
        ];
    }
}
