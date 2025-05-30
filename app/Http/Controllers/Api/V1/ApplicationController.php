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

use App\Models\Application;
use App\Models\UserRole;
use App\Http\Resources\ApplicationResource;
use App\Http\Resources\UserAppResource;
use App\Traits\ApiResponse;

use Exception;

/**
 * @OA\Tag(
 *     name="Applications",
 *     description="API Endpoints for application management"
 * )
 */
class ApplicationController extends Controller
{
    use ApiResponse;

    /**
     * @OA\Get(
     *     path="/api/v1/applications",
     *     summary="Get list of applications",
     *     tags={"Applications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="search",
     *         in="query",
     *         description="Search applications by name or code",
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
     *         description="List of applications retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Applications retrieved successfully"),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/ApplicationResource"))
     *         )
     *     )
     * )
     */
    public function index(Request $request)
    {
        try {
            $query = Application::query();

            // Search functionality
            if ($search = $request->query('search')) {
                $query->where(function($q) use ($search) {
                    $q->where('name', 'ilike', "%{$search}%")
                      ->orWhere('code', 'ilike', "%{$search}%")
                      ->orWhere('alias', 'ilike', "%{$search}%");
                });
            }

            // Filter by platform type
            if ($platformType = $request->query('platform_type')) {
                $query->where('platform_type', $platformType);
            }

            // Filter by status
            if ($status = $request->query('is_active') == 1 ? true : false) {
                $query->where('is_active', $status);
            }

            $sortParams = $request->query('sort');
            if ($sortParams) {
                $sorts = explode(';', $sortParams);
                $allowedSortFields = ['created_at', 'name', 'code', 'alias', 'is_active', 'platform_type'];
    
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
                ApplicationResource::collection($data),
                'Applications retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Post(
     *     path="/api/v1/applications",
     *     summary="Create a new application",
     *     tags={"Applications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"code","name","base_url"},
     *             @OA\Property(property="code", type="string", example="APP001"),
     *             @OA\Property(property="name", type="string", example="My Application"),
     *             @OA\Property(property="alias", type="string", example="MyApp"),
     *             @OA\Property(property="description", type="string", example="Description of the application"),
     *             @OA\Property(property="base_url", type="string", example="https://myapp.example.com"),
     *             @OA\Property(property="login_url", type="string", example="https://myapp.example.com/login"),
     *             @OA\Property(property="platform_type", type="string", example="web"),
     *             @OA\Property(property="visibility", type="string", example="public"),
     *             @OA\Property(property="is_active", type="boolean", example=true)
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Application created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Application created successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/ApplicationResource")
     *         )
     *     )
     * )
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'code' => 'required|string|max:50|unique:applications',
            'name' => 'required|string|max:255',
            'alias' => 'nullable|string|max:50',
            'description' => 'nullable|string',
            'base_url' => 'required|url',
            'login_url' => 'required|url',
            'platform_type' => 'required|string|in:Web,Mobile,Desktop',
            'visibility' => 'required|string|in:Public,Internal',
            // 'image' => 'nullable|image|mimes:jpg,jpeg,png|max:2048'
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $clientId = bin2hex(random_bytes(8));
            $clientSecret = bin2hex(random_bytes(16));

            $params = $validator->validated();
            $params['uuid'] = Str::uuid();
            $params['code'] = strtolower($params['code']);

            // Handle image upload
            if ($request->hasFile('image')) {
                $file = $request->file('image');
                $filename = Str::slug($params['code']) . '.' . $file->getClientOriginalExtension();
                $path = $file->storeAs('public/applications', $filename);
                $params['image'] = Storage::url($path);
            }

            $application = Application::create($params);

            DB::commit();

            return $this->successResponse(
                new ApplicationResource($application),
                'Aplikasi berhasil dibuat.',
                201
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Get(
     *     path="/api/v1/applications/{uuid}",
     *     summary="Get application details",
     *     tags={"Applications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Application UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Application details retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Application details retrieved successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/ApplicationResource")
     *         )
     *     )
     * )
     */
    public function show($uuid)
    {
        try {
            $application = Application::where('uuid', $uuid)->first();

            if (!$application) {
                return $this->errorResponse('Data aplikasi tidak ditemukan.', 404);
            }
            
            return $this->successResponse(
                new ApplicationResource($application),
                'Application retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Put(
     *     path="/api/v1/applications/{uuid}",
     *     summary="Update application details",
     *     tags={"Applications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Application UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="Updated Application"),
     *             @OA\Property(property="alias", type="string", example="UpdatedApp"),
     *             @OA\Property(property="description", type="string", example="Updated description"),
     *             @OA\Property(property="base_url", type="string", example="https://updated-app.example.com"),
     *             @OA\Property(property="login_url", type="string", example="https://updated-app.example.com/login"),
     *             @OA\Property(property="platform_type", type="string", example="web"),
     *             @OA\Property(property="visibility", type="string", example="public"),
     *             @OA\Property(property="is_active", type="boolean", example=true)
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Application updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Application updated successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/ApplicationResource")
     *         )
     *     )
     * )
     */
    public function update(Request $request, $uuid)
    {
        $application = Application::where('uuid', $uuid)->first();

        if (!$application) {
            return $this->errorResponse('Data aplikasi tidak ditemukan.', 404);
        }

        $validator = Validator::make($request->all(), [
            'code' => 'required|string|max:50|unique:applications,code,'.$application->id,
            'name' => 'required|string|max:255',
            'alias' => 'nullable|string|max:50',
            'description' => 'nullable|string',
            'base_url' => 'required|url',
            'login_url' => 'required|url',
            'platform_type' => 'required|string|in:Web,Mobile,Desktop',
            'visibility' => 'required|string|in:Public,Internal',
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        try {
            DB::beginTransaction();

            $params = $validator->validated();
            $params['code'] = strtolower($params['code']);

            // Handle image upload
            if ($request->hasFile('image')) {
                // Delete old image
                if ($application->image) {
                    Storage::delete(str_replace('/storage', 'public', $application->image));
                }

                $file = $request->file('image');
                $filename = Str::slug($params['code']) . '.' . $file->getClientOriginalExtension();
                $path = $file->storeAs('public/applications', $filename);
                $params['image'] = Storage::url($path);
            }

            $application->update($params);

            DB::commit();

            return $this->successResponse(
                new ApplicationResource($application),
                'Aplikasi berhasil diperbarui.'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Delete(
     *     path="/api/v1/applications/{uuid}",
     *     summary="Delete an application",
     *     tags={"Applications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Application UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Application deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Application deleted successfully")
     *         )
     *     )
     * )
     */
    public function destroy($uuid)
    {
        try {
            DB::beginTransaction();

            $application = Application::where('uuid', $uuid)->first();

            if (!$application) {
                return $this->errorResponse('Data aplikasi tidak ditemukan.', 404);
            }
            
            // Check if application has any user roles
            if ($application->userRoles()->exists()) {
                return $this->errorResponse('Tidak dapat menghapus aplikasi karena masih ada pengguna yang menggunakan aplikasi ini.', 422);
            }

            // Delete image if exists
            if ($application->image) {
                Storage::delete(str_replace('/storage', 'public', $application->image));
            }

            $application->delete();

            DB::commit();

            return $this->successResponse(
                null,
                'Aplikasi berhasil dihapus.'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Put(
     *     path="/api/v1/applications/{uuid}/status",
     *     summary="Update application status",
     *     tags={"Applications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Application UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Application status updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Application status updated successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/ApplicationResource")
     *         )
     *     )
     * )
     * */
    public function updateStatus(Request $request, $uuid)
    {
        try {
            DB::beginTransaction();

            $application = Application::where('uuid', $uuid)->first();

            if (!$application) {
                return $this->errorResponse('Data aplikasi tidak ditemukan.', 404);
            }
            
            $application->update(['is_active' => !$application->is_active]);

            DB::commit();

            return $this->successResponse(
                new ApplicationResource($application),
                'Status aplikasi berhasil diperbarui.'
            );
        } catch (Exception $e) {
            DB::rollBack();
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Get(
     *     path="/api/v1/applications/{uuid}/users",
     *     summary="Get users assigned to an application",
     *     tags={"Applications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Application UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Users retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Users retrieved successfully"),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/UserRoleResource"))
     *         )
     *     )
     * )
     */
    public function showUserApplication(Request $request, $uuid)
    {
        try {
            $query = UserRole::distinct()
                ->select('user_roles.id', 'users.code', 'users.full_name', 'users.username', 'roles.display_name as role', 'user_roles.uuid', 'user_roles.assigned_at', 'user_roles.assigned_by', 'user_roles.created_at', 'user_roles.updated_at')
                ->join('users', 'users.id', '=', 'user_roles.user_id')
                ->join('applications', 'applications.id', '=', 'user_roles.app_id')
                ->join('roles', 'roles.id', '=', 'user_roles.role_id')
                ->where('applications.uuid', $uuid);

            if ($search = $request->query('search')) {
                $query->where(function ($q) use ($search) {
                    $q->where('users.username', 'ilike', "%$search%")
                      ->orWhere('users.full_name', 'ilike', "%$search%")
                      ->orWhere('users.code', 'ilike', "%$search%")
                      ->orWhere('roles.display_name', 'ilike', "%$search%");
                });
            }
            
            $data = $query->orderBy('users.full_name', 'asc')->orderBy('roles.display_name', 'asc')->get();

            return $this->successResponse(
                UserAppResource::collection($data),
                'User applications retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Get(
     *     path="/api/v1/auth/me/applications",
     *     summary="Get my applications",
     *     tags={"Applications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Response(
     *         response=200,
     *         description="My applications retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="My applications retrieved successfully"),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/ApplicationResource"))
     *         )
     *     )
     * )
     */
    public function myApplication(Request $request) 
    {
        $user = auth()->user();

        try {
            $query = Application::distinct()
                ->select('applications.*')
                ->join('user_roles', 'applications.id', '=', 'user_roles.app_id')
                ->join('users', 'users.id', '=', 'user_roles.user_id')
                ->join('roles', 'roles.id', '=', 'user_roles.role_id')
                ->where('applications.is_active', true)
                ->where('applications.code' , '!=', 'sso')
                ->where('applications.code' , '!=', 'SSO')
                ->where('user_roles.user_id', $user->id);
            
            $data = $query->orderBy('applications.name', 'asc')->get();

            return $this->successResponse(
                ApplicationResource::collection($data),
                'My applications retrieved successfully'
            );
        } catch (Exception $ex) {
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }
}
