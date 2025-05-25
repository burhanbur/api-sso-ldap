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

class NotificationController extends Controller
{
    use ApiResponse;

    public function index(Request $request)
    {
        try {
            $data = Notification::with(['user', 'application'])->orderBy('created_at', 'desc')->paginate(10);

            return $this->successResponse(
                NotificationResource::collection($data),
                'Notifications retrieved successfully'
            );
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }

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

            $clientId = $request->header('x-api-key');
            if (!$clientId) {
                return $this->errorResponse('Client ID is required', 400);
            }

            $app = Application::where('client_id', $clientId)->first();
            if (!$app) {
                return $this->errorResponse('Application not found', 404);
            }

            $data = Notification::create([
                'uuid' => Str::uuid(),
                'user_id' => auth()->user()->id,
                'app_id' => $app->id,
                'type' => $request->type, // info, success, warning, error
                'subject' => $request->subject,
                'content' => $request->text,
                'detail_url' => $request->detail_url
            ]);

            DB::commit();

            return $this->successResponse(
                $data,
                'Notification stored successfully'
            );
        } catch (Exception $ex){
            DB::rollBack();
            Log::error('Error storing notification: ' . $ex->getMessage() . ' at ' . $ex->getFile() . ':' . $ex->getLine());
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    public function updateReadStatus(Request $request, $uuid)
    {
        try {
            $notification = Notification::with(['user', 'application'])->where('uuid', $uuid)->first();
            if (!$notification) {
                return $this->errorResponse('Notification not found', 404);
            }

            $notification->update([
                'is_read' => 1,
                'read_at' => now()
            ]);

            return $this->successResponse(
                new NotificationResource($notification),
                'Notification status updated successfully'
            );
        } catch (Exception $ex) {
            Log::error('Error updating notification: ' . $ex->getMessage() . ' at ' . $ex->getFile() . ':' . $ex->getLine());
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    public function destroy($uuid)
    {
        try {
            $notification = Notification::where('uuid', $uuid)->first();
            if (!$notification) {
                return $this->errorResponse('Notification not found', 404);
            }

            $notification->delete();

            return $this->successResponse(null, 'Notification deleted successfully');
        } catch (Exception $ex) {
            Log::error('Error deleting notification: ' . $ex->getMessage() . ' at ' . $ex->getFile() . ':' . $ex->getLine());
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }

    public function markAllAsRead()
    {
        try {
            $userId = auth()->user()->id;
            Notification::where('user_id', $userId)->update(['is_read' => true, 'read_at' => now()]);

            return $this->successResponse(null, 'All notifications marked as read');
        } catch (Exception $ex) {
            Log::error('Error marking all notifications as read: ' . $ex->getMessage() . ' at ' . $ex->getFile() . ':' . $ex->getLine());
            return $this->errorResponse($ex->getMessage(), 500);
        }
    }
}
