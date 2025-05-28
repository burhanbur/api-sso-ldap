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

use App\Models\User;
use App\Models\Role;
use App\Models\UserRole;
use App\Http\Resources\UserRoleResource;
use App\Utilities\Ldap;
use App\Traits\ApiResponse;

use Exception;

/**
 * @OA\Tag(
 *     name="User Roles",
 *     description="API Endpoints for user role management"
 * )
 */
class UserRoleController extends Controller
{
    use ApiResponse;

    /**
     * @OA\Get(
     *     path="/api/v1/user-roles",
     *     summary="Get list of user roles",
     *     tags={"User Roles"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="user_id",
     *         in="query",
     *         description="Filter by user ID",
     *         required=false,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Parameter(
     *         name="app_id",
     *         in="query",
     *         description="Filter by application ID",
     *         required=false,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Parameter(
     *         name="role_id",
     *         in="query",
     *         description="Filter by role ID",
     *         required=false,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         description="Page number",
     *         required=false,
     *         @OA\Schema(type="integer", default=1)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="List of user roles retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User roles retrieved successfully"),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/UserRoleResource"))
     *         )
     *     )
     * )
     */
    public function index(Request $request)
    {
        try {
            $query = UserRole::with(['user', 'role', 'application', 'entityType', 'assigner']);

            if ($request->filled('user_id')) {
                $query->where('user_id', $request->user_id);
            }
        
            if ($request->filled('app_id')) {
                $query->where('app_id', $request->app_id);
            }
        
            if ($request->filled('role_id')) {
                $query->where('role_id', $request->role_id);
            }

            $data = $query->paginate(10);

            return $this->successResponse(
                UserRoleResource::collection($data),
                'User roles retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Post(
     *     path="/api/v1/user-roles",
     *     summary="Assign a role to a user",
     *     tags={"User Roles"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"user_id", "role_id", "app_id"},
     *             @OA\Property(property="user_id", type="integer", example=1),
     *             @OA\Property(property="role_id", type="integer", example=1),
     *             @OA\Property(property="app_id", type="integer", example=1),
     *             @OA\Property(property="entity_type_id", type="integer", example=1),
     *             @OA\Property(property="entity_id", type="string", example="DEPT001"),
     *             @OA\Property(property="assigned_by", type="integer", example=1)
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Role assigned to user successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Role assigned to user successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/UserRoleResource")
     *         )
     *     )
     * )
     */
    public function store(Request $request)
    {
        $response = $this->errorResponse($this->errMessage);

        $validator = Validator::make($request->all(), [
            'user_id' => [
                'required',
                'exists:users,id',
                'unique:user_roles,user_id,NULL,id,role_id,' . $request->role_id . ',app_id,' . $request->app_id
            ],
            'role_id' => 'required|exists:roles,id',
            'app_id' => 'required|exists:applications,id',
            'entity_type_id' => 'nullable|exists:entity_types,id',
            'entity_id' => 'nullable|string|max:50',
        ], [
            'user_id.required' => 'User ID is required',
            'user_id.exists' => 'User ID does not exist',
            'user_id.unique' => 'This user already has this role in this application',
            'role_id.required' => 'Role ID is required',
            'role_id.exists' => 'Role ID does not exist',
            'app_id.required' => 'Application ID is required',
            'app_id.exists' => 'Application ID does not exist',
            'entity_type_id.exists' => 'Entity Type ID does not exist',
            'entity_id.string' => 'Entity ID must be a string',
            'entity_id.max' => 'Entity ID may not be greater than 50 characters',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $data = $validator->validated();
            $data['assigned_by'] = auth()->id();
            $data['assigned_at'] = now();
            $data['uuid'] = Str::uuid();

            $userRole = UserRole::create($data);

            DB::commit();
            
            $response = $this->successResponse(
                $userRole,
                'Peran pengguna berhasil ditetapkan.'
            );
        } catch (Exception $ex) {
            DB::rollBack();
            $response = $this->errorResponse($ex->getMessage(), 500);
        }

        return $response;
    }

    /**
     * @OA\Delete(
     *     path="/api/v1/user-roles/{uuid}",
     *     summary="Remove a role from a user",
     *     tags={"User Roles"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="User Role UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Role removed from user successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Role removed from user successfully")
     *         )
     *     )
     * )
     */
    public function destroy($uuid)
    {
        try {
            DB::beginTransaction();

            $userRole = UserRole::where('uuid', $uuid)->first();

            if (!$userRole) {
                return $this->errorResponse('Data pengguna tidak ditemukan.', 404);
            }

            $appId = $userRole->app_id;
            $userRole->delete();

            $data = UserRole::join('users', 'users.id', '=', 'user_roles.user_id')
                ->join('applications', 'applications.id', '=', 'user_roles.app_id')
                ->join('roles', 'roles.id', '=', 'user_roles.role_id')
                ->where('applications.id', $appId)
                ->select('users.id', 'users.code', 'users.full_name', 'users.username', 'roles.display_name as role', 'user_roles.uuid')
                ->distinct()
                ->orderBy('users.full_name', 'asc')
                ->get();

            DB::commit();

            return $this->successResponse(
                $data,
                'Peran pengguna berhasil dicabut.'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }
}
