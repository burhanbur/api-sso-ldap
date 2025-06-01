<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_access_tokens', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignId('user_id')->constrained('users');
            $table->string('client_id')->foreign('client_id')->references('client_id')->on('appliations')->onDelete('cascade');
            $table->string('access_token')->unique();
            $table->string('refresh_token')->unique()->nullable();
            $table->timestamp('expires_at');
            $table->json('scopes')->nullable();
            $table->timestamps();

            $table->index(['access_token']);
            $table->index(['refresh_token']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_access_tokens');
    }
};
