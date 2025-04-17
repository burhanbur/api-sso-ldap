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
        ];
    }
}
