<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Usuario;
use Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */

    // public function __construct()
    // {
    //     $this->middleware('auth:api', ['except' => ['login']]);
    // }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {

        // $credentials = $request->only('de_nome_usuario', 'de_senha');

        // $usuario = Usuario::create([
        //     'de_nome_usuario' => 'Cris',
        //     'de_senha' => Hash::make('cris'),
        // ]);

        $credentials = [
            'de_nome_usuario' => $request->input('de_nome_usuario'),
            'password' => $request->input('de_senha')
        ];

        // dd($senha);
        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh(Request $request)
    {
        $refreshToken = $request->input('refreshToken');

        // Encontre o usuário usando o refresh token
        $user = Usuario::where('refresh_token', $refreshToken)->first();

        // Verifica se o usuário foi encontrado
        if (!$user) {
            return response()->json(['error' => 'Invalid refresh token'], 401);
        }

        // Autenticar o usuário manualmente
        auth()->login($user);

        // Gera um novo token JWT
        $newToken = auth()->refresh();

        // Atualiza o refresh token (opcional)
        $newRefreshToken = Str::random(60);
        $user->update(['refresh_token' => $newRefreshToken]);

        return response()->json([
            'token' => $newToken,
            'refresh_token' => $newRefreshToken
        ]);
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'refresh_token' => $this->generateRefreshToken(),
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }

    protected function generateRefreshToken()
    {
        // Lógica para gerar um refresh token
        // Isso geralmente envolve a criação de um token e o armazenamento associado ao usuário
        $refreshToken = Str::random(60); // Gera um token aleatório para o exemplo

        // Armazene o refresh token no banco de dados associado ao usuário
        // Exemplo (supondo que você tenha um campo para refresh_token na tabela de usuários):
        auth()->user()->update(['refresh_token' => $refreshToken]);

        return $refreshToken;
    }
}
