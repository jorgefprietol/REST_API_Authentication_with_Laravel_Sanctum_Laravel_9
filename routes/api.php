<?php

use App\Http\Controllers\AuthApi;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('register',[AuthApi::class,'register']);
Route::post('login',[AuthApi::class,'login']);

Route::middleware('auth:sanctum')->group(function (){
    Route::post('logout',[AuthApi::class,'logout']);
    Route::get('user', function (Request $request){
       return $request->user();
    });
});
