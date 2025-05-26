<!DOCTYPE html>
<html>
<head>
    <title>OAuth Error</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
    <div class="min-h-screen flex items-center justify-center">
        <div class="bg-white p-8 rounded-lg shadow-md w-96">
            <div class="text-center mb-8">
                <h2 class="text-2xl font-bold text-red-600">OAuth Error</h2>
                <p class="text-gray-600 mt-2">{{ $error }}</p>
                @if(isset($error_description))
                    <p class="text-sm text-gray-500 mt-2">{{ $error_description }}</p>
                @endif
            </div>
            
            <div class="text-center">
                <a href="{{ url('/') }}" class="text-blue-500 hover:text-blue-700">Back to Home</a>
            </div>
        </div>
    </div>
</body>
</html>
