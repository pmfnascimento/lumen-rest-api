<?php

namespace App\Http\Controllers;

use App\Models\User;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use GuzzleHttp\Exception\ClientException;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $email = $request->email;
        $password = $request->password;

        // Check if field is not empty

        if (empty($email) or empty($password)) {
            return response()->json(['status' => 'error', 'message' => 'You must fill all fields']);
        }

        $client = new Client();

        try {
            return $client->post(config('services.passport.login_endpoint'), [
                "form_params" => [
                    "client_secret" => config('services.passport.client_secret'),
                    "grant_type" => "password",
                    "client_id" => config('services.passport.client_id'),
                    "username" => $request->email,
                    "password" => $request->password


                ]
            ]);
        } catch (ClientException $e) {
            $response = $e->getResponse();
            $responseBodyAsString = $response->getBody()->getContents();
            return response()->json(['status' => 'error', 'message' => $responseBodyAsString]);
        }
    }

    public function register(Request $request)
    {
        $name = $request->name;
        $email = $request->email;
        $password = $request->password;

        if (empty($email) or empty($password) or empty($name)) {
            return response()->json(['status' => 'error', 'message' => 'You must fill all fields']);
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['status' => 'error', 'message' => 'You must enter valid email']);
        }

        if (strlen($password) < 6) {
            return response()->json(['status' => 'error', 'message' => 'Password should be min 6 character']);
        }

        if (User::where('email', '=', $email)->exists()) {
            return response()->json(['status' => 'error', 'message' => 'User already exists with this email']);
        }

        try {
            $user = new User();
            $user->name = $request->name;
            $user->email = $request->email;
            $user->password = app('hash')->make($password);

            if ($user->save()) {
                return $this->login($request);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => 'error', 'message' => $e->getMessage()]);
        }
    }

    public function logout(Request $request)
    {
        try {
            auth()->user()->tokens()->each(function ($token) {
                $token->delete();
            });
            return response()->json(['status' => 'success', 'message' => 'Logged out successfully']);
        } catch (\Exception $e) {
            return response()->json(['status' => 'error', 'message' => $e->getMessage()]);
        }
    }
}
