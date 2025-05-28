<?php

namespace App\Http\Resources;

/**
 * @OA\Schema(
 *     schema="ApplicationResource",
 *     type="object",
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="uuid", type="string", format="uuid", example="550e8400-e29b-41d4-a716-446655440000"),
 *     @OA\Property(property="code", type="string", example="APP001"),
 *     @OA\Property(property="name", type="string", example="My Application"),
 *     @OA\Property(property="alias", type="string", example="MyApp"),
 *     @OA\Property(property="description", type="string", example="Description of the application"),
 *     @OA\Property(property="base_url", type="string", example="https://myapp.example.com"),
 *     @OA\Property(property="login_url", type="string", example="https://myapp.example.com/login"),
 *     @OA\Property(property="platform_type", type="string", example="web"),
 *     @OA\Property(property="visibility", type="string", example="public"),
 *     @OA\Property(property="is_active", type="boolean", example=true),
 *     @OA\Property(property="image", type="string", example="https://myapp.example.com/logo.png"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 *
 * @OA\Schema(
 *     schema="UserResource",
 *     type="object",
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="uuid", type="string", format="uuid", example="550e8400-e29b-41d4-a716-446655440000"),
 *     @OA\Property(property="username", type="string", example="john.doe"),
 *     @OA\Property(property="code", type="string", example="EMP001"),
 *     @OA\Property(property="full_name", type="string", example="John Doe"),
 *     @OA\Property(property="nickname", type="string", example="John"),
 *     @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
 *     @OA\Property(property="alt_email", type="string", format="email", example="john.alt@example.com"),
 *     @OA\Property(property="join_date", type="string", format="date", example="2023-01-01"),
 *     @OA\Property(property="title", type="string", example="Software Engineer"),
 *     @OA\Property(property="status", type="string", example="active"),
 *     @OA\Property(
 *         property="app_access",
 *         type="array",
 *         @OA\Items(
 *             type="object",
 *             @OA\Property(property="uuid", type="string", format="uuid"),
 *             @OA\Property(property="code", type="string"),
 *             @OA\Property(property="name", type="string"),
 *             @OA\Property(property="base_url", type="string")
 *         )
 *     )
 * )
 * 
 * @OA\Schema(
 *     schema="RoleResource",
 *     type="object",
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="uuid", type="string", format="uuid", example="550e8400-e29b-41d4-a716-446655440000"),
 *     @OA\Property(property="name", type="string", example="admin"),
 *     @OA\Property(property="display_name", type="string", example="Administrator"),
 *     @OA\Property(property="description", type="string", example="System administrator role"),
 *     @OA\Property(
 *         property="role_type",
 *         type="object",
 *         @OA\Property(property="id", type="integer"),
 *         @OA\Property(property="uuid", type="string", format="uuid"),
 *         @OA\Property(property="code", type="string"),
 *         @OA\Property(property="name", type="string"),
 *         @OA\Property(property="description", type="string")
 *     ),
 *     @OA\Property(
 *         property="scope_type",
 *         type="object",
 *         @OA\Property(property="id", type="integer"),
 *         @OA\Property(property="uuid", type="string", format="uuid"),
 *         @OA\Property(property="code", type="string"),
 *         @OA\Property(property="name", type="string"),
 *         @OA\Property(property="description", type="string")
 *     ),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 * 
 * @OA\Schema(
 *     schema="NotificationResource",
 *     type="object",
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="uuid", type="string", format="uuid", example="550e8400-e29b-41d4-a716-446655440000"),
 *     @OA\Property(property="user_id", type="integer", example=1),
 *     @OA\Property(property="app_id", type="integer", example=1),
 *     @OA\Property(property="type", type="string", example="info"),
 *     @OA\Property(property="subject", type="string", example="New Message"),
 *     @OA\Property(property="content", type="string", example="You have a new message"),
 *     @OA\Property(property="detail_url", type="string", example="/messages/123"),
 *     @OA\Property(property="is_read", type="boolean", example=false),
 *     @OA\Property(property="read_at", type="string", format="date-time", nullable=true),
 *     @OA\Property(
 *         property="application",
 *         type="object",
 *         @OA\Property(property="id", type="integer"),
 *         @OA\Property(property="uuid", type="string", format="uuid"),
 *         @OA\Property(property="code", type="string"),
 *         @OA\Property(property="name", type="string")
 *     ),
 *     @OA\Property(
 *         property="user",
 *         type="object",
 *         @OA\Property(property="id", type="integer"),
 *         @OA\Property(property="uuid", type="string", format="uuid"),
 *         @OA\Property(property="username", type="string"),
 *         @OA\Property(property="full_name", type="string"),
 *         @OA\Property(property="code", type="string"),
 *         @OA\Property(property="email", type="string", format="email")
 *     ),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 * 
 * @OA\Schema(
 *     schema="UserRoleResource",
 *     type="object",
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="uuid", type="string", format="uuid", example="550e8400-e29b-41d4-a716-446655440000"),
 *     @OA\Property(
 *         property="user",
 *         type="object",
 *         @OA\Property(property="id", type="integer"),
 *         @OA\Property(property="uuid", type="string", format="uuid"),
 *         @OA\Property(property="username", type="string"),
 *         @OA\Property(property="code", type="string"),
 *         @OA\Property(property="full_name", type="string"),
 *         @OA\Property(property="nickname", type="string"),
 *         @OA\Property(property="email", type="string", format="email"),
 *         @OA\Property(property="alt_email", type="string", format="email"),
 *         @OA\Property(property="join_date", type="string", format="date"),
 *         @OA\Property(property="title", type="string"),
 *         @OA\Property(property="status", type="string")
 *     ),
 *     @OA\Property(
 *         property="assigned_by",
 *         type="object",
 *         ref="#/components/schemas/UserResource"
 *     ),
 *     @OA\Property(property="assigned_at", type="string", format="date-time"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 */
class Schemas {}
