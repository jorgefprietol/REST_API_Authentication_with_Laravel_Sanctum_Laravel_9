<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthApi extends Controller
{
    public function response($user): JsonResponse
    {

        $token = $user->createToken( str()->random(40) )->plainTextToken;

        return response()->json([
            'user' => $user,
            'token' => $token,
            'token_type' => 'Bearer'
        ]);

    }

    public function register(Request $request): JsonResponse
    {
        //prueba

        $request->validate([
            'name' => 'required|min:3',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:4|confirmed'
        ]);

        $user = User::create([
            'name' => ucwords($request->name),
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        return $this->response($user);

    }

    public function login(Request $request): JsonResponse
    {

        $cred = $request->validate([
            'email' => 'required|email|exists:users',
            'password' => 'required|min:4'
        ]);

        if(!Auth::attempt( $cred ))
        {

            return response()->json([
                'message' => 'Unauthorized.'
            ], 401);

        }

        return $this->response( Auth::user());

    }

    public function logout()
    {
        Auth::user()->tokens()->delete();

        return response()->json([
            'message' => 'You have successfully logged out and token was successfull deleted.'
        ]);

    }

}
