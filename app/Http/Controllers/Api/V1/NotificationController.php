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
use App\Models\Notification;
use App\Http\Resources\NotificationResource;
use App\Traits\ApiResponse;

use Exception;

/**
 * @OA\Tag(
 *     name="Notifications",
 *     description="API Endpoints for notification management"
 * )
 */
class NotificationController extends Controller
{
    use ApiResponse;

    /**
     * @OA\Get(
     *     path="/api/v1/notifications",
     *     summary="Get list of notifications for authenticated user",
     *     tags={"Notifications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         description="Page number",
     *         required=false,
     *         @OA\Schema(type="integer", default=1)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="List of notifications retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Notifications retrieved successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/notifications"),
     *             @OA\Property(property="method", type="string", example="GET"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=5),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/NotificationResource"))
     *         )
     *     )
     * )
     */
    public function index(Request $request)
    {
        try {
            $user = auth()->user();
            $data = Notification::with(['user', 'application'])
                ->where('user_id', $user->id)
                ->orderBy('created_at', 'desc')
                ->paginate(10);

            return $this->successResponse(
                NotificationResource::collection($data),
                'Notifications retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * @OA\Post(
     *     path="/api/v1/notifications",
     *     summary="Create a new notification",
     *     tags={"Notifications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"type","subject","content"},
     *             @OA\Property(property="type", type="string", example="info"),
     *             @OA\Property(property="subject", type="string", example="New Message"),
     *             @OA\Property(property="content", type="string", example="You have a new message"),
     *             @OA\Property(property="detail_url", type="string", example="/messages/123"),
     *             @OA\Property(property="app_id", type="integer", example=1)
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Notification created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Notification created successfully"),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/notifications"),
     *             @OA\Property(property="method", type="string", example="POST"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="data", ref="#/components/schemas/NotificationResource")
     *         )
     *     )
     * )
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'type' => 'required|string|in:info,success,warning,error',
            'subject' => 'required|string|max:255',
            'content' => 'required|string',
            'detail_url' => 'nullable|string'
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors()->first(), 422);
        }

        try {
            DB::beginTransaction();

            $appId = $request->header('x-app-id');
            if (!$appId) {
                return $this->errorResponse('ID aplikasi wajib diisi.', 400);
            }

            $app = Application::where('uuid', $appId)->first();
            if (!$app) {
                return $this->errorResponse('ID aplikasi tidak ditemukan.', 404);
            }

            $data = Notification::create([
                'uuid' => Str::uuid(),
                'user_id' => auth()->user()->id,
                'app_id' => $app->id,
                'type' => $request->type, // info, success, warning, error
                'subject' => $request->subject,
                'content' => $request->content,
                'detail_url' => $request->detail_url
            ]);

            DB::commit();

            return $this->successResponse(
                NotificationResource::collection($data),
                'Berhasil menyimpan notifikasi.'
            );
        } catch (Exception $ex){
            DB::rollBack();
            Log::error('Error storing notification: ' . $ex->getMessage() . ' at ' . $ex->getFile() . ':' . $ex->getLine());
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    /**
     * @OA\Put(
     *     path="/api/v1/notifications/{uuid}",
     *     summary="Mark a notification as read",
     *     tags={"Notifications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Notification UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Notification marked as read successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/notifications/53e6b0f8-4f7c-4a3a-b0f8-4f7c4a3ab0f8"),
     *             @OA\Property(property="method", type="string", example="PUT"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=1),
     *             @OA\Property(property="message", type="string", example="Notification marked as read successfully")
     *         )
     *     )
     * )
     */
    public function updateReadStatus(Request $request, $uuid)
    {
        try {
            $notification = Notification::with(['user', 'application'])->where('uuid', $uuid)->first();
            if (!$notification) {
                return $this->errorResponse('Data notifikasi tidak ditemukan.', 404);
            }

            $notification->update([
                'is_read' => 1,
                'read_at' => date('Y-m-d H:i:s')
            ]);

            return $this->successResponse(
                new NotificationResource($notification),
                'Notifikasi telah ditandai sebagai dibaca.'
            );
        } catch (Exception $ex) {
            Log::error('Error updating notification: ' . $ex->getMessage() . ' at ' . $ex->getFile() . ':' . $ex->getLine());
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    /**
     * @OA\Delete(
     *     path="/api/v1/notifications/{uuid}",
     *     summary="Delete a notification",
     *     tags={"Notifications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Parameter(
     *         name="uuid",
     *         in="path",
     *         description="Notification UUID",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Notification deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/notifications/53e6b0f8-4f7c-4a3a-b0f8-4f7c4a3ab0f8"),
     *             @OA\Property(property="method", type="string", example="DELETE"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=0),
     *             @OA\Property(property="message", type="string", example="Notification deleted successfully")
     *         )
     *     )
     * )
     */
    public function destroy($uuid)
    {
        try {
            $notification = Notification::where('uuid', $uuid)->first();
            if (!$notification) {
                return $this->errorResponse('Data notifikasi tidak ditemukan.', 404);
            }

            $notification->delete();

            return $this->successResponse(null, 'Berhasil menghapus notifikasi.');
        } catch (Exception $ex) {
            Log::error('Error deleting notification: ' . $ex->getMessage() . ' at ' . $ex->getFile() . ':' . $ex->getLine());
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    /**
     * @OA\Put(
     *     path="/api/v1/notifications/read-all",
     *     summary="Mark all notifications as read",
     *     tags={"Notifications"},
     *     security={{ "bearerAuth": {} }},
     *     @OA\Response(
     *         response=200,
     *         description="All notifications marked as read successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="url", type="string", example="http://localhost:8000/api/v1/notifications/read-all"),
     *             @OA\Property(property="method", type="string", example="PUT"),
     *             @OA\Property(property="timestamp", type="string", example="2023-06-01 10:00:00"),
     *             @OA\Property(property="total_data", type="integer", example=0),
     *             @OA\Property(property="message", type="string", example="All notifications marked as read successfully")
     *         )
     *     )
     * )
     */
    public function markAllAsRead()
    {
        try {
            $userId = auth()->user()->id;
            Notification::where(['user_id' => $userId, 'is_read' => false])->update(['is_read' => true, 'read_at' => now()]);

            return $this->successResponse(null, 'Semua notifikasi telah ditandai sebagai dibaca.');
        } catch (Exception $ex) {
            Log::error('Error marking all notifications as read: ' . $ex->getMessage() . ' at ' . $ex->getFile() . ':' . $ex->getLine());
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }
}
