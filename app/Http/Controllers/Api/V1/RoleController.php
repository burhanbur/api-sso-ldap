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

use App\Models\Role;
use App\Http\Resources\RoleResource;
use App\Utilities\Ldap;
use App\Traits\ApiResponse;

use Exception;

/**
 * @OA\Tag(
 *     name="Roles",
 *     description="API Endpoints for role management"
 * )
 */
class RoleController extends Controller
{
    use ApiResponse;

    /**
     * @OA\Get(
     *     path="/api/v1/roles",
     *     summary="Get list of roles",
     *     tags={"Roles"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="search",
     *         in="query",
     *         description="Search roles by name",
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
     *     @OA\Response(
     *         response=200,
     *         description="List of roles retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Roles retrieved successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/roles"),
     *             @OA\Property(property="method", type="string", example="GET"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=5),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/RoleResource"))
     *         )
     *     )
     * )
     */
    public function index(Request $request)
    {
        try {
            $query = Role::with(['roleType', 'scopeType']);

            if ($search = $request->query('search')) {
                $query->where(function($q) use ($search) {
                    $q->where('name', 'ilike', "%{$search}%")
                      ->orWhere('display_name', 'ilike', "%{$search}%")
                      ->orWhere('description', 'ilike', "%{$search}%");
                });
            }

            if ($roleType = $request->query('role_type_id')) {
                $query->where('role_type_id', $roleType);
            }

            if ($scopeType = $request->query('scope_type_id')) {
                $query->where('scope_type_id', $scopeType);
            }

            $sortParams = $request->query('sort');
            if ($sortParams) {
                $sorts = explode(';', $sortParams);
                $allowedSortFields = ['created_at', 'name', 'display_name'];
    
                foreach ($sorts as $sort) {
                    [$field, $direction] = explode(',', $sort) + [null, 'asc'];
                    $direction = strtolower($direction) === 'desc' ? 'desc' : 'asc';
    
                    if (in_array($field, $allowedSortFields)) {
                        $query->orderBy($field, $direction);
                    } else {
                        $query->orderBy('name');
                    }
                }
            } else {
                $query->orderBy('name');
            }

            $data = $query->paginate((int) $request->query('limit', 10));

            return $this->successResponse(
                RoleResource::collection($data),
                'Roles retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Post(
     *     path="/api/v1/roles",
     *     summary="Create a new role",
     *     tags={"Roles"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","display_name"},
     *             @OA\Property(property="name", type="string", example="admin"),
     *             @OA\Property(property="display_name", type="string", example="Administrator"),
     *             @OA\Property(property="description", type="string", example="System administrator role"),
     *             @OA\Property(property="role_type_id", type="integer", example=1),
     *             @OA\Property(property="scope_type_id", type="integer", example=1)
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Role created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Role created successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/roles"),
     *             @OA\Property(property="method", type="string", example="POST"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", ref="#/components/schemas/RoleResource")
     *         )
     *     )
     * )
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|unique:roles',
            'display_name' => 'required|string|max:255',
            'description' => 'nullable|string',
            'role_type_id' => 'nullable|exists:role_types,id',
            'scope_type_id' => 'nullable|exists:scopes,id'
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $role = Role::create([
                'uuid' => Str::uuid(),
                'name' => $request->name,
                'display_name' => $request->display_name,
                'description' => $request->description,
                'role_type_id' => $request->role_type_id,
                'scope_type_id' => $request->scope_type_id
            ]);

            DB::commit();

            return $this->successResponse(
                new RoleResource($role->load(['roleType', 'scopeType'])),
                'Peran baru berhasil dibuat.',
                201
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Get(
     *     path="/api/v1/roles/{uuid}",
     *     summary="Get role details",
     *     tags={"Roles"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Role UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Role details retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Role details retrieved successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/roles/53e8b9b8-0c4b-4b0d-8a0d-4b0d8a0d4b0d"),
     *             @OA\Property(property="method", type="string", example="GET"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", ref="#/components/schemas/RoleResource")
     *         )
     *     )
     * )
     */
    public function show($uuid)
    {
        try {
            $role = Role::with(['roleType', 'scopeType'])
                ->where('uuid', $uuid)
                ->first();

            if (!$role) {
                return $this->errorResponse('Data peran tidak ditemukan.', 404);
            }
            
            return $this->successResponse(
                new RoleResource($role),
                'Role retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Put(
     *     path="/api/v1/roles/{uuid}",
     *     summary="Update role details",
     *     tags={"Roles"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Role UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="admin"),
     *             @OA\Property(property="display_name", type="string", example="Administrator"),
     *             @OA\Property(property="description", type="string", example="System administrator role"),
     *             @OA\Property(property="role_type_id", type="integer", example=1),
     *             @OA\Property(property="scope_type_id", type="integer", example=1)
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Role updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Role updated successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/roles/53e8b9b8-0c4b-4b0d-8a0d-4b0d8a0d4b0d"),
     *             @OA\Property(property="method", type="string", example="PUT"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", ref="#/components/schemas/RoleResource")
     *         )
     *     )
     * )
     */
    public function update(Request $request, $uuid)
    {
        $role = Role::where('uuid', $uuid)->first();

        if (!$role) {
            return $this->errorResponse('Data peran tidak ditemukan.', 404);
        }

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|unique:roles,name,'.$role->id,
            'display_name' => 'required|string|max:255',
            'description' => 'nullable|string',
            'role_type_id' => 'nullable|exists:role_types,id',
            'scope_type_id' => 'nullable|exists:scopes,id'
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $role->update([
                'name' => $request->name,
                'display_name' => $request->display_name,
                'description' => $request->description,
                'role_type_id' => $request->role_type_id,
                'scope_type_id' => $request->scope_type_id
            ]);

            DB::commit();

            return $this->successResponse(
                new RoleResource($role->load(['roleType', 'scopeType'])),
                'Peran berhasil diperbarui.'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Delete(
     *     path="/api/v1/roles/{uuid}",
     *     summary="Delete a role",
     *     tags={"Roles"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Role UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Role deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/roles/53e8b9b8-0c4b-4b0d-8a0d-4b0d8a0d4b0d"),
     *             @OA\Property(property="method", type="string", example="DELETE"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=0),
     *             @OA\Property(property="message", type="string", example="Role deleted successfully")
     *         )
     *     )
     * )
     */
    public function destroy($uuid)
    {
        try {
            DB::beginTransaction();

            $role = Role::where('uuid', $uuid)->first();

            if (!$role) {
                return $this->errorResponse('Data peran tidak ditemukan.', 404);
            }
            
            // Check if role has any users
            if ($role->users()->exists()) {
                return $this->errorResponse('Tidak dapat menghapus peran karena masih ada pengguna yang menggunakan peran ini.', 422);
            }

            $role->delete();

            DB::commit();

            return $this->successResponse(
                null,
                'Peran berhasil dihapus.'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }
}
