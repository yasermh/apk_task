<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;

use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct() {
        $this->middleware('auth:api', ['except' => ['login', 'register','send_password_reset_sms','change_password']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request){
    	$validator = Validator::make($request->all(), [
            'phone_number' => 'required|regex:/(09)[0-9]{9}/|digits:11|numeric',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->createNewToken($token);
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|regex:/^[ آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهیئ\s]+$/|between:2,100',
            'phone_number' => 'required|regex:/(09)[0-9]{9}/|digits:11|numeric|unique:users',
            'password' => 'required|string|min:6',
        ],[
            'name.regex' => 'نام و نام خانوادگی باید حروف فارسی باشد',
        ]);

        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create(array_merge(
                    $validator->validated(),
                    ['password' => bcrypt($request->password)]
                ));

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }


    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() {
        auth()->logout();

        return response()->json(['message' => 'User successfully signed out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh() {
        return $this->createNewToken(auth()->refresh());
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile() {
        return response()->json(auth()->user());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }

    public function send_password_reset_sms(Request $request){
        $validator = Validator::make($request->all(), [
            'phone_number' => 'required|regex:/(09)[0-9]{9}/|digits:11|numeric',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
        $user=User::where('phone_number',$request->phone_number)->first();
        if($user==null){
            return response()->json([
                'message' => 'phone number does not exist.'
            ],500);
        }
        $code=rand(10000,99999);
        $user->update([
            'remember_token' => Hash::make($code),
        ]);
        return response()->json([
                'message' => 'we have sent a code to your phone number.',
                'code' =>$code
        ],200);
    }
    public function change_password(Request $request){
        $validator = Validator::make($request->all(), [
            'phone_number' => 'required|regex:/(09)[0-9]{9}/|digits:11|numeric',
            'remember_token' => 'required|digits:5|numeric',
            'password' =>'required|string|min:6'
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
        $user=User::where('phone_number',$request->phone_number)->first();
        if($user==null){
            return response()->json([
                'message' => 'phone number does not exist.'
            ],500);
        }
        if(Hash::check($request->remember_token, $user->remember_token, [])) {
            $user->password = Hash::make($request->password);
            $user->save();
            return response()->json('User password change successfully', 200);

        }
        return response()->json(['error' => 'code is not valid'], 500);
    }
    public function password(Request $request){
        $validator = Validator::make($request->all(), [
            'password' => 'required|string|min:6|max:20|confirmed',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
        $user=auth()->user();
        $user->password =bcrypt($request['password']);

    }

}