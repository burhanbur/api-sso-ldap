<?php

namespace App\Http\Controllers\Api\V1;

use OpenApi\Annotations as OA;

/**
 * @OA\Info(
 *     version="1.0.0",
 *     title="UPER IDP API Documentation",
 *     description="API documentation for UPER IDP SSO System (CENTRAL)",
 *     @OA\Contact(
 *         email="burhan.mafazi@universitaspertamina.ac.id"
 *     )
 * )
 * 
 * @OA\Server(
 *     url=L5_SWAGGER_CONST_HOST,
 *     description="API Server"
 * )
 * 
 * @OA\SecurityScheme(
 *     type="http",
 *     description="Login with username and password to get the authentication token",
 *     name="Token based Based",
 *     in="header",
 *     scheme="bearer",
 *     bearerFormat="JWT",
 *     securityScheme="bearerAuth",
 * )
 * 
 * @OA\Tag(
 *     name="Authentication",
 *     description="API Endpoints for User Authentication"
 * )
 * @OA\Tag(
 *     name="Users",
 *     description="API Endpoints for User Management"
 * )
 * @OA\Tag(
 *     name="Applications",
 *     description="API Endpoints for Application Management"
 * )
 * @OA\Tag(
 *     name="Roles",
 *     description="API Endpoints for Role Management"
 * )
 * @OA\Tag(
 *     name="User Roles",
 *     description="API Endpoints for User Role Management"
 * )
 * @OA\Tag(
 *     name="Notifications",
 *     description="API Endpoints for Notification Management"
 * )
 * @OA\Tag(
 *     name="Client Apps",
 *     description="API Endpoints Only for Client Apps Management"
 * )
 */
class Controller extends \App\Http\Controllers\Controller
{
}
