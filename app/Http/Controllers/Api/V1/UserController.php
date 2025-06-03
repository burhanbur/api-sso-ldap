<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

use App\Models\Notification;
use App\Models\User;
use App\Models\UserRole;
use App\Http\Resources\UserResource;
use App\Utilities\Ldap;
use App\Utilities\Utils;
use App\Traits\ApiResponse;
use App\Imports\ReadExcelImport;

use Maatwebsite\Excel\Facades\Excel;

use Exception;

/**
 * @OA\Tag(
 *     name="Users",
 *     description="API Endpoints for user management"
 * )
 */
class UserController extends Controller
{
    use ApiResponse;

    /**
     * @OA\Get(
     *     path="/api/v1/users",
     *     summary="Get list of users",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="search",
     *         in="query",
     *         description="Search users by name, email, or username",
     *         required=false,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         description="Page number",
     *         required=false,
     *         @OA\Schema(type="integer", default=1)
     *     ),
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         description="Items per page",
     *         required=false,
     *         @OA\Schema(type="integer", default=10)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="List of users retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Users retrieved successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users"),
     *             @OA\Property(property="method", type="string", example="GET"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=5),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/UserResource")),
     *             @OA\Property(property="pagination", type="object",
     *                 @OA\Property(property="total", type="integer", example=5),
     *                 @OA\Property(property="per_page", type="integer", example=10),
     *                 @OA\Property(property="current_page", type="integer", example=1),
     *                 @OA\Property(property="last_page", type="integer", example=1),
     *                 @OA\Property(property="from", type="integer", example=1),
     *                 @OA\Property(property="to", type="integer", example=5)
     *             )
     *         )
     *     )
     * )
     */
    public function index(Request $request)
    {
        $response = $this->errorResponse($this->errMessage);

        try {
            $query = User::with(['userRoles.role', 'userRoles.application', 'userRoles.entityType']);

            if ($search = $request->query('search')) {
                $query->where(function ($q) use ($search) {
                    $q->where('username', 'ilike', "%$search%")
                      ->orWhere('full_name', 'ilike', "%$search%")
                      ->orWhere('code', 'ilike', "%$search%")
                      ->orWhere('email', 'ilike', "%$search%")
                      ->orWhere('nickname', 'ilike', "%$search%");
                });
            }
    
            if ($status = $request->query('status')) {
                $query->where('status', $status);
            }

            $sortParams = $request->query('sort');
            if ($sortParams) {
                $sorts = explode(';', $sortParams);
                $allowedSortFields = ['created_at', 'full_name', 'code', 'username', 'status'];
    
                foreach ($sorts as $sort) {
                    [$field, $direction] = explode(',', $sort) + [null, 'asc'];
                    $direction = strtolower($direction) === 'desc' ? 'desc' : 'asc';
    
                    if (in_array($field, $allowedSortFields)) {
                        $query->orderBy($field, $direction);
                    } else {
                        $query->orderBy('full_name');
                    }
                }
            } else {
                $query->orderBy('full_name');
            }
    
            $data = $query->paginate((int) $request->query('limit', 10));
            
            $response = $this->successResponse(
                // $users,
                UserResource::collection($data),
                'Users retrieved successfully'
            );
        } catch (Exception $ex) {
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    /**
     * @OA\Get(
     *     path="/api/v1/users/{uuid}",
     *     summary="Get user details",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="User UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User details retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User details retrieved successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users/5e9b6c5e-4bde-11d1-9f0e-1234567890ab"),
     *             @OA\Property(property="method", type="string", example="GET"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", ref="#/components/schemas/UserResource")
     *         )
     *     )
     * )
     */
    public function show($uuid)
    {
        $response = $this->errorResponse($this->errMessage);
        
        try {
            $user = User::with(['userRoles.role', 'userRoles.application', 'userRoles.entityType'])->where('uuid', $uuid)->first();

            if (!$user) {
                return $this->errorResponse('Data pengguna tidak ditemukan.', 404);
            }
            
            $response = $this->successResponse(
                new UserResource($user),
                'User retrieved successfully'
            );
        } catch (Exception $ex) {
            $response = $this->errorResponse($ex->getMessage(), 500);
        }
        
        return $response;
    }

    /**
     * @OA\Post(
     *     path="/api/v1/users",
     *     summary="Create a new user",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"username","email","full_name"},
     *             @OA\Property(property="username", type="string", example="john.doe"),
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
     *             @OA\Property(property="full_name", type="string", example="John Doe"),
     *             @OA\Property(property="nickname", type="string", example="John"),
     *             @OA\Property(property="alt_email", type="string", format="email", example="john.alt@example.com"),
     *             @OA\Property(property="join_date", type="string", format="date", example="2023-01-01"),
     *             @OA\Property(property="title", type="string", example="Software Engineer"),
     *             @OA\Property(property="status", type="string", example="active")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User created successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users"),
     *             @OA\Property(property="method", type="string", example="POST"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="data", ref="#/components/schemas/UserResource")
     *         )
     *     )
     * )
     */
    public function store(Request $request)
    {
        $response = $this->errorResponse($this->errMessage);

        $validator = Validator::make($request->all(), [
            'username' => 'required|string|max:255|unique:users',
            'password' => 'required|string|min:8',
            'password_confirmation' => 'required|string|same:password',
            'code' => 'required|string|max:255',
            'full_name' => 'required|string|max:255',
            'nickname' => 'nullable|string|max:255',
            'email' => 'nullable|email',
            'alt_email' => 'nullable|email',
            'join_date' => 'nullable|date',
            'title' => 'nullable|string|max:255',
            'status' => 'nullable|string|in:Aktif,Tidak Aktif',
            'app_access' => 'nullable|array',
            'app_access.*.app_id' => 'required|exists:applications,id',
            'app_access.*.role_id' => 'required|exists:roles,id',
            'app_access.*.entity_type_id' => 'nullable|exists:entity_types,id',
            'app_access.*.entity_id' => 'nullable|string|max:255',
        ], [
            'username.unique' => 'Username already exists',
            'password.min' => 'Password must be at least 8 characters',
            'password_confirmation.same' => 'Password confirmation does not match',
            'email.email' => 'Email must be a valid email address',
            'alt_email.email' => 'Alternate email must be a valid email address',
            'status.in' => 'Status must be either Aktif or Tidak Aktif',
            'app_access.array' => 'User roles must be provided as an array',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $plainPassword = $request->password;
            $bcryptPassword = bcrypt($request->password);

            $params = [];
            $params['uuid'] = Str::uuid();
            $params['username'] = $request->username;
            $params['password'] = $bcryptPassword;
            $params['code'] = $request->code;
            $params['full_name'] = $request->full_name;
            $params['nickname'] = $request->nickname ?? $request->full_name;
            $params['email'] = $request->email;
            $params['alt_email'] = $request->alt_email;
            $params['join_date'] = $request->join_date ?? now()->format('Y-m-d');
            $params['title'] = $request->title;
            $params['status'] = $request->status ?? 'Aktif';

            $user = User::create($params);
            $this->_syncUserAccess($user, $request->app_access);
            $sync = Ldap::syncUserFromLdap($user, 'store', $plainPassword);

            if (!$sync) {
                return $this->errorResponse('Gagal terhubung ke server direktori. Silakan cek kredensial admin LDAP atau konfigurasi server.', 500);
            }

            DB::commit();
            
            $response = $this->successResponse(
                new UserResource($user),
                'Data pengguna baru berhasil dibuat.'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    /**
     * @OA\Put(
     *     path="/api/v1/users/{uuid}",
     *     summary="Update user details",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="User UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
     *             @OA\Property(property="full_name", type="string", example="John Doe"),
     *             @OA\Property(property="nickname", type="string", example="John"),
     *             @OA\Property(property="alt_email", type="string", format="email", example="john.alt@example.com"),
     *             @OA\Property(property="join_date", type="string", format="date", example="2023-01-01"),
     *             @OA\Property(property="title", type="string", example="Software Engineer"),
     *             @OA\Property(property="status", type="string", example="active")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User updated successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users/51f9b4c0-1f1a-4b0c-8f0e-1f1a4b0c8f0e"),
     *             @OA\Property(property="method", type="string", example="PUT"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="data", ref="#/components/schemas/UserResource")
     *         )
     *     )
     * )
     */
    public function update(Request $request, $uuid)
    {
        $response = $this->errorResponse($this->errMessage);

        $user = User::where('uuid', $uuid)->first();

        if (!$user) {
            return $this->errorResponse('Data pengguna tidak ditemukan.', 404);
        }

        $validator = Validator::make($request->all(), [
            'username' => "required|string|max:255|unique:users,username,{$user->id}",
            'code' => 'required|string|max:255',
            'full_name' => 'required|string|max:255',
            'nickname' => 'nullable|string|max:255',
            'email' => 'nullable|email',
            'alt_email' => 'nullable|email',
            'join_date' => 'nullable|date',
            'title' => 'nullable|string|max:255',
            'status' => 'nullable|string|in:Aktif,Tidak Aktif',
            'app_access' => 'nullable|array',
            'app_access.*.app_id' => 'required|exists:applications,id',
            'app_access.*.role_id' => 'required|exists:roles,id',
            'app_access.*.entity_type_id' => 'nullable|exists:entity_types,id',
            'app_access.*.entity_id' => 'nullable|string|max:255',
        ], [
            'username.unique' => 'Username already exists',
            'email.email' => 'Email must be a valid email address',
            'alt_email.email' => 'Alternate email must be a valid email address',
            'status.in' => 'Status must be either Aktif or Tidak Aktif',
            'app_access.array' => 'User roles must be provided as an array',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $params = [
                'username' => $request->input('username') ?? $user->username,
                'code' => $request->input('code') ?? $user->code,
                'full_name' => $request->input('full_name') ?? $user->full_name,
                'nickname' => $request->input('nickname') ?? $user->nickname,
                'email' => $request->input('email') ?? $user->email,
                'alt_email' => $request->input('alt_email') ?? $user->alt_email,
                'join_date' => $request->input('join_date') ?? $user->join_date,
                'title' => $request->input('title') ?? $user->title,
                'status' => $request->input('status', 'Aktif') ?? $user->status,
            ];

            $user->update($params);
            $this->_syncUserAccess($user, $request->app_access);
            $sync = Ldap::syncUserFromLdap($user, 'update');

            if (!$sync) {
                return $this->errorResponse('Gagal terhubung ke server direktori. Silakan cek kredensial admin LDAP atau konfigurasi server.', 500);
            }

            DB::commit();

            $response = $this->successResponse(
                new UserResource($user),
                'Data pengguna berhasil diperbarui.'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    /**
     * Sync user access (roles) with the given user.
     *
     * @param User $user
     * @param array $appAccess
     * @return void
     */
    private function _syncUserAccess(User $user, array $appAccess = []): void
    {
        $assignedBy = auth()->user()->id;
        $now = now();

        $existingAccess = UserRole::where('user_id', $user->id)->get();

        $incomingKeys = [];

        foreach ($appAccess as $value) {
            $key = $value['app_id'] . '-' . $value['role_id'];
            $incomingKeys[] = $key;

            $access = $existingAccess->firstWhere(fn ($item) =>
                $item->app_id == $value['app_id'] &&
                $item->role_id == $value['role_id']
            );

            if ($access) {
                $access->update([
                    'entity_type_id' => $value['entity_type_id'],
                    'entity_id' => $value['entity_id'],
                    'assigned_by' => $assignedBy,
                    'assigned_at' => $now,
                ]);
            } else {
                UserRole::create([
                    'uuid' => Str::uuid(),
                    'user_id' => $user->id,
                    'role_id' => $value['role_id'],
                    'app_id' => $value['app_id'],
                    'entity_type_id' => $value['entity_type_id'],
                    'entity_id' => $value['entity_id'],
                    'assigned_by' => $assignedBy,
                    'assigned_at' => $now,
                ]);
            }
        }

        foreach ($existingAccess as $oldAccess) {
            $key = $oldAccess->app_id . '-' . $oldAccess->role_id;

            if (!in_array($key, $incomingKeys)) {
                $oldAccess->delete();
            }
        }
    }

    /**
     * @OA\Put(
     *     path="/api/v1/users/{uuid}/status",
     *     summary="Update user status",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="User UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 @OA\Property(
     *                     property="status",
     *                     type="string",
     *                     enum={"Aktif", "Tidak Aktif"},
     *                     example="Aktif"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User status updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User status updated successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users/5e9b6c5d-3b9d-4b9a-b9a3-5e9b6c5d3b9a/status"),
     *             @OA\Property(property="method", type="string", example="PUT"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="data", ref="#/components/schemas/UserResource")
     *         )
     *     )
     * )
     */
    public function updateStatus(Request $request, $uuid)
    {
        $response = $this->errorResponse($this->errMessage);

        $user = User::where('uuid', $uuid)->first();

        if (!$user) {
            return $this->errorResponse('Data pengguna tidak ditemukan.', 404);
        }

        $validator = Validator::make($request->all(), [
            'status' => 'nullable|string|in:Aktif,Tidak Aktif',
        ], [
            'status.in' => 'Status must be either Aktif or Tidak Aktif',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $params = [
                'status' => $request->input('status', 'Aktif') ?? $user->status,
            ];

            $user->update($params);
            $sync = Ldap::syncUserFromLdap($user, 'update');

            if (!$sync) {
                return $this->errorResponse('Gagal terhubung ke server direktori. Silakan cek kredensial admin LDAP atau konfigurasi server.', 500);
            }

            DB::commit();

            $response = $this->successResponse(
                new UserResource($user),
                'Data status pengguna berhasil diperbarui.'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }
    
    /** 
     * @OA\Post(
     *     path="/api/v1/users/generate-username",
     *     summary="Generate username",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"name"},
     *                 @OA\Property(
     *                     property="name",
     *                     type="string",
     *                     example="John Doe"
     *                 ),
     *                 @OA\Property(
     *                     property="type",
     *                     type="string",
     *                     example="staff"
     *                 ),
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Username generated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Username generated successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users/generate-username"),
     *             @OA\Property(property="method", type="string", example="POST"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", type="object", example="johndoe")
     *         )
     *     )
     * )
     */
    public function generateUsername(Request $request)
    {
        $name = $request->name;
        $type = $request->type ?? 'staff';

        $username = Utils::getInstance()->generateUsername($name, $type);

        return $this->successResponse(
            $username,
            'Username berhasil dibuat.'
        );
    }

    /**
     * @OA\Post(
     *     path="/api/v1/users/me/profiles",
     *     summary="Update my profile",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"full_name"},
     *             @OA\Property(property="full_name", type="string", example="John Doe"),
     *             @OA\Property(property="nickname", type="string", example="John"),
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
     *             @OA\Property(property="alt_email", type="string", format="email", example="john.alt@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="My profile updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="My profile updated successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users/me/profiles"),
     *             @OA\Property(property="method", type="string", example="POST"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", ref="#/components/schemas/UserResource")
     *         )
     *     )
     * )
     */
    public function updateMyProfile(Request $request)
    {
        $response = $this->errorResponse($this->errMessage);

        $user = auth()->user();

        if (!$user) {
            return $this->errorResponse('Data pengguna tidak ditemukan.', 404);
        }

        $validator = Validator::make($request->all(), [
            'full_name' => 'required|string|max:255',
            'nickname' => 'nullable|string|max:255',
            'email' => 'nullable|email',
            'alt_email' => 'nullable|email',
        ], [
            'email.email' => 'Email must be a valid email address',
            'alt_email.email' => 'Alternate email must be a valid email address',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $params = [
                'full_name' => $request->input('full_name') ?? $user->full_name,
                'nickname' => $request->input('nickname') ?? $user->nickname,
                'email' => $request->input('email') ?? $user->email,
                'alt_email' => $request->input('alt_email') ?? $user->alt_email,
            ];

            $user->update($params);
            $sync = Ldap::syncUserFromLdap($user, 'update');

            if (!$sync) {
                return $this->errorResponse('Gagal terhubung ke server direktori. Silakan cek kredensial admin LDAP atau konfigurasi server.', 500);
            }

            DB::commit();

            $response = $this->successResponse(
                new UserResource($user),
                'Profil pengguna berhasil diperbarui.'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    /**
     * @OA\Post(
     *     path="/api/v1/users/import",
     *     summary="Import users from Excel file",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"file"},
     *                 @OA\Property(
     *                     property="file",
     *                     type="file",
     *                     format="binary"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Users imported successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Users imported successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users/import"),
     *             @OA\Property(property="method", type="string", example="POST"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/UserResource"))
     *         )
     *     )
     * )
     */
    public function import(Request $request) 
    {
        $validator = Validator::make($request->all(), [
            'file' => 'required|file|mimes:xlsx,xls'
        ]);

        if ($validator->fails()) {
            $this->errorResponse($validator->errors(), 422);
        }

        try {
            $importErrors = [];
            $realPath = $request->file('file');
            $rows = (Excel::toArray(new ReadExcelImport, $realPath)[0]) ?? [];
            $utils = new Utils;

            foreach ($rows as $key => $data) {
                $full_name = $data[0];
                $username = $utils->generateUsername($data[0]);
                $password = $data[1];
                $code = $data[2];
                $email = $data[3];
                $nickname = @$data[4];
                $alt_email = @$data[5];
                $join_date = @$data[6];
                $title = @$data[7];
                $status = 'Aktif';

                if (empty($full_name) || empty($username) || empty($password) || empty($code) || empty($email)) {
                    continue;
                }
                
                DB::beginTransaction();

                try {
                    $plainPassword = $password;
                    $bcryptPassword = bcrypt($password);

                    $params = [];
                    $params['uuid'] = Str::uuid();
                    $params['username'] = $username;
                    $params['password'] = $bcryptPassword;
                    $params['code'] = $code;
                    $params['full_name'] = $full_name;
                    $params['nickname'] = $nickname ?? $full_name;
                    $params['email'] = $email;
                    $params['alt_email'] = $alt_email;
                    $params['join_date'] = $join_date ? date('Y-m-d', strtotime($join_date)) : now()->format('Y-m-d');
                    $params['title'] = $title;
                    $params['status'] = $status;

                    $user = User::create($params);

                    if (!$user) {
                        throw new Exception('Gagal membuat pengguna baru.');
                    }
                    
                    $this->_syncUserAccess($user, []);
                    $sync = Ldap::syncUserFromLdap($user, 'store', $plainPassword);

                    if (!$sync) {
                        throw new Exception('Gagal terhubung ke server direktori. Silakan cek kredensial admin LDAP atau konfigurasi server.');
                    }

                    DB::commit();
                } catch (Exception $exLoop) {
                    DB::rollback();
                    // Hey ChatGPT, buatkan log error di sini dan juga notifikasi (entah berupa file report atau apapun yang penting user tahu kalau ada yang gagal diimport)

                    $importErrors[] = [
                        'baris' => $key + 1,
                        'nama' => $full_name,
                        'username' => $username,
                        'email' => $email,
                        'alasan' => $exLoop->getMessage()
                    ];
                }
            }

            $reportPath = null;

            if (!empty($importErrors)) {
                $reportName = 'import_errors_' . now()->format('Ymd_His') . '.csv';
                $reportPath = storage_path('app/public/' . $reportName);
                
                $fp = fopen($reportPath, 'w');
                fputcsv($fp, ['Baris', 'Nama Lengkap', 'Username', 'Email', 'Alasan Gagal']);

                foreach ($importErrors as $error) {
                    fputcsv($fp, [$error['baris'], $error['nama'], $error['username'], $error['email'], $error['alasan']]);
                }

                fclose($fp);
            }

            return $this->successResponse(
                [
                    'preview_errors' => $importErrors,
                    'error_report' => $reportPath ? asset('storage/' . basename($reportPath)) : null,
                ], count($importErrors) > 0
                ? 'Import selesai dengan beberapa error. Silakan cek file laporan.'
                : 'Data pengguna berhasil diimpor.'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    /**
     * @OA\Delete(
     *     path="/api/v1/users/{uuid}",
     *     summary="Delete user",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="User UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User deleted successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users/5e9b6c5e-4bde-11d1-9f0e-1234567890ab"),
     *             @OA\Property(property="method", type="string", example="DELETE"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Internal server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Internal server error"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users/5e9b6c5e-4bde-11d1-9f0e-1234567890ab"),
     *             @OA\Property(property="method", type="string", example="DELETE"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00")
     *         )
     *     )
     * )
     */
    public function delete($uuid) 
    {
        try {
            DB::beginTransaction();

            $user = User::where('uuid', $uuid)->first();

            if (!$user) {
                throw new Exception('Pengguna tidak ditemukan.');
            }

            $fullName = $user->full_name;
            UserRole::where('user_id', $user->id)->delete();
            Notification::where('user_id', $user->id)->delete();
            $user->delete();

            $sync = Ldap::deleteLdapUser($user->username);

            if (!$sync) {
                throw new Exception('Gagal terhubung ke server direktori. Silakan cek kredensial admin LDAP atau konfigurasi server.');
            }

            DB::commit();

            return $this->successResponse(null, 'Pengguna ' . $fullName . ' berhasil dihapus.');
        } catch (Exception $ex) {
            DB::rollBack();
            
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    /**
     * @OA\Get(
     *     path="/api/v1/users/ldap",
     *     summary="Get list of users from LDAP",
     *     tags={"Users"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Response(
     *         response=200,
     *         description="User data retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User data retrieved successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/users/ldap"),
     *             @OA\Property(property="method", type="string", example="GET"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/UserResource"))
     *         )
     *     )
     * )
     */
    public function userLdap()
    {
        // if (!$ldapConnection = Ldap::connectToLdap()) {
        //     return null;
        // }

        // $dn = "uid=lmawati," . env('LDAP_PEOPLE_OU') . "," . env('LDAP_BASE_DN');
        // @ldap_delete($ldapConnection, $dn);

        return $this->successResponse(
            Ldap::listLdapUsers(),
            'User data retrieved successfully'
        );
    }
}
