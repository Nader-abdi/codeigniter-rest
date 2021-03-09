<?php

namespace yidas\rest;

use Firebase\JWT\JWT;
use yidas\http\Request;
use yidas\http\Response;


/**
 * RESTful API Controller
 *
 * @author  Nick Tsai <myintaer@gmail.com>
 * @version 1.6.1
 * @link    https://github.com/yidas/codeigniter-rest/
 * @see     https://github.com/yidas/codeigniter-rest/blob/master/examples/RestController.php
 * @see     https://en.wikipedia.org/wiki/Representational_state_transfer#Relationship_between_URL_and_HTTP_methods
 *
 * Controller extending:
 * ```php
 * class My_controller extends yidas\rest\Controller {}
 * ```
 *
 * Route setting:
 * ```php
 * $route['resource_name'] = '[Controller]/route';
 * $route['resource_name/(:num)'] = '[Controller]/route/$1';
 * ```
 */
class Controller extends \MY_Controller
{
    const JWT_SECRET_KEY = JWT_TOKEN;

    /**
     * RESTful API resource routes
     *
     * public function index() {}
     * protected function store($requestData=null) {}
     * protected function show($resourceID) {}
     * protected function update($resourceID, $requestData=null) {}
     * protected function delete($resourceID=null) {}
     *
     * @var array RESTful API table of routes & actions
     */
    protected $routes = [
        'index' => 'index',
        'store' => 'store',
        'show' => 'show',
        'update' => 'update',
        'delete' => 'delete',
    ];

    /**
     * Behaviors of actions
     *
     * @var array
     */
    private $behaviors = [
        'index' => null,
        'store' => null,
        'show' => null,
        'update' => null,
        'delete' => null,
    ];

    /**
     * Pre-setting format
     *
     * @var string yidas\http\Response format
     */
    protected $format;

    /**
     * Body Format usage switch
     *
     * @var bool Default $bodyFormat for json()
     */
    protected $bodyFormat = false;

    /**
     * @var object yidas\http\Request;
     */
    protected $request;

    /**
     * @var object yidas\http\Response;
     */
    protected $response;

    function __construct()
    {
        parent::__construct();

        // Request initialization
        $this->request = new Request;
        // Response initialization
        $this->response = new Response;
        // Response setting
        if ($this->format) {
            $this->response->setFormat($this->format);
        }
    }

    /**
     * Route bootstrap
     *
     * For Codeigniter route setting to implement RESTful API
     *
     * Without routes setting, `resource/{route-alias}` URI pattern is a limitation which CI3 would
     * first map `controller/action` URI into action() instead of index($action)
     *
     * @param int|string Resource ID
     */
    public function route($resourceID = NULL)
    {
        switch ($this->request->getMethod()) {
            case 'POST':
                if (!$resourceID) {
                    return $this->_action(['store', $this->request->getBodyParams()]);
                }
                break;
            case 'PATCH':
                // PATCH could only allow single element
                if (!$resourceID) {
                    return $this->_defaultAction();
                }
                break;
            case 'PUT':
                return $this->_action(['update', $resourceID, $this->request->getBodyParams()]);
                break;
            case 'DELETE':
                return $this->_action(['delete', $resourceID, $this->request->getBodyParams()]);
                break;
            case 'GET':
            default:
                if ($resourceID) {
                    return $this->_action(['show', $resourceID]);
                } else {
                    return $this->_action(['index']);
                }
                break;
        }
    }

    /**
     * Alias of route()
     *
     * `resource/api` URI pattern
     */
    public function api($resourceID = NULL)
    {
        return $this->route($resourceID);
    }

    /**
     * Alias of route()
     *
     * `resource/ajax` URI pattern
     */
    public function ajax($resourceID = NULL)
    {
        return $this->route($resourceID);
    }

    /**
     * Output by JSON format with optinal body format
     *
     * @param array|mixed Callback data body, false will remove body key
     * @param bool Enable body format
     * @param int HTTP Status Code
     * @param string Callback message
     * @return string Response body data
     *
     * @deprecated 1.3.0
     * @example
     *  json(false, true, 401, 'Login Required', 'Unauthorized');
     */
    protected function json($data = [], $bodyFormat = null, $statusCode = null, $message = null)
    {
        // Check default Body Format setting if not assigning
        $bodyFormat = ($bodyFormat !== null) ? $bodyFormat : $this->bodyFormat;

        if ($bodyFormat) {
            // Pack data
            $data = $this->_format($statusCode, $message, $data);
        } else {
            // JSON standard of RFC4627
            $data = is_array($data) ? $data : [$data];
        }

        return $this->response->json($data, $statusCode);
    }

    /**
     * Format Response Data
     *
     * @param int Callback status code
     * @param string Callback status text
     * @param array|mixed|bool Callback data body, false will remove body key
     * @return array Formated array data
     * @deprecated 1.3.0
     */
    protected function _format($statusCode = null, $message = null, $body = false)
    {
        $format = [];
        // Status Code field is necessary
        $format['code'] = ($statusCode)
            ?: $this->response->getStatusCode();
        // Message field
        if ($message) {
            $format['message'] = $message;
        }
        // Body field
        if ($body !== false) {
            $format['data'] = $body;
        }

        return $format;
    }

    /**
     * Pack array data into body format
     *
     * You could override this method for your application standard
     *
     * @param array|mixed $data Original data
     * @param int HTTP Status Code
     * @param string Callback message
     * @return array Packed data
     * @example
     *  $packedData = pack(['bar'=>'foo], 401, 'Login Required');
     */
    protected function pack($data, $statusCode = 200, $message = null)
    {
        $packBody = [];

        // Status Code
        if ($statusCode) {

            $packBody['code'] = $statusCode;
        }
        // Message
        if ($message) {

            $packBody['message'] = $message;
        }
        // Data
        if (is_array($data) || is_string($data)) {

            $packBody['data'] = $data;
        }

        return $packBody;
    }

    /**
     * Default Action
     */
    protected function _defaultAction()
    {
        /* Response sample code */
        // $response->data = ['foo'=>'bar'];
        // $response->setStatusCode(401);

        // Codeigniter 404 Error Handling
        show_404();
    }

    /**
     * Set behavior to a action before route
     *
     * @param String $action
     * @param $access
     * @return boolean Result
     */
    protected function _setBehavior($action, $access = false)
    {
        if (array_key_exists($action, $this->behaviors)) {

            $this->behaviors[$action] = $access;
            return true;
        }

        return false;
    }

    /**
     * Action processor for route
     *
     * @param array Elements contains method for first and params for others
     */
    private function _action($params)
    {
        // Shift and get the method
        $method = array_shift($params);

        // Behavior
        if (!$this->behaviors[$method]) {
            $this->throwError(405, 'Method Not Allowed');
        }

        if (!isset($this->routes[$method])) {
            $this->throwError(404, 'The endpoint you are looking for is not found.');
        }

        // Get corresponding method name
        $method = $this->routes[$method];
        if (!method_exists($this, $method)) {
            $this->_defaultAction();
        }

        return call_user_func_array([$this, $method], $params);
    }

    public function validateRequestPost()
    {
        if (strpos($_SERVER['CONTENT_TYPE'] ,'application/json') === false) {
            $this->throwError(403, 'The only acceptable content type is application/json.');
        }
    }
    public function validateRequestGet($id)
    {
        if(!is_numeric($id)){
            $this->throwError(403, 'Segment only acceptable numeric');
        }
    }

    public function validateParams($type = null , $fieldName, $value, $isRequired = false)
    {

        if ($isRequired == true && $value == "") {
            $this->throwError(400, "The $fieldName field is required.");
        }
        if (!empty($type)) {


            switch ($type) {
                case 'email':
                    if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                        $this->throwError(406, "Invalid email format");
                    }
                    break;
                case 'password':
                    if (strlen($value) < 5 ){
                        $this->throwError(406, "Password must be greater than 5 ");
                    }
                    break;
                case 'number':
                    $phone = preg_replace('/[^0-9]/', '', $value);
                    if( strlen($phone) <= 9 ){
                        $this->throwError(406, "Invalid number format");
                    }
                    break;
                case 'compare':
                    if ($fieldName != $value){
                        $this->throwError(406, "Password not equal");;
                    }
            }
        }
        return $value;
    }

    public function validateJson()
    {
        json_decode($this->request->getRawBody());
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->throwError(400, 'Bad Request Json Invalid');
        };

    }

    public function throwError(int $statusCode, string $message)
    {
        header('Content-Type: application/json');
        $data = ['message' => $message];
        $http = [
            100 => '100 Continue',
            101 => '101 Switching Protocols',
            200 => '200 OK',
            201 => '201 Created',
            202 => '202 Accepted',
            203 => '203 Non-Authoritative Information',
            204 => '204 No Content',
            205 => '205 Reset Content',
            206 => '206 Partial Content',
            300 => '300 Multiple Choices',
            301 => '301 Moved Permanently',
            302 => '302 Found',
            303 => '303 See Other',
            304 => '304 Not Modified',
            305 => '305 Use Proxy',
            307 => '307 Temporary Redirect',
            400 => '400 Bad Request',
            401 => '401 Unauthorized',
            402 => '402 Payment Required',
            403 => '403 Forbidden',
            404 => '404 Not Found',
            405 => '405 Method Not Allowed',
            406 => '406 Not Acceptable',
            407 => '407 Proxy Authentication Required',
            408 => '408 Request Time-out',
            409 => '409 Conflict',
            410 => '410 Gone',
            411 => '411 Length Required',
            412 => '412 Precondition Failed',
            413 => '413 Request Entity Too Large',
            414 => '414 Request-URI Too Large',
            415 => '415 Unsupported Media Type',
            416 => '416 Requested Range Not Satisfiable',
            417 => '417 Expectation Failed',
            500 => '500 Internal Server Error',
            501 => '501 Not Implemented',
            502 => '502 Bad Gateway',
            503 => '503 Service Unavailable',
            504 => '504 Gateway Time-out',
            505 => '505 HTTP Version Not Supported',
        ];
        $this->response->json($data, $http[$statusCode]);
        die;
    }

    public function generateToken($user): string
    {
        try {
            return JWT::encode([
                'iat' => time(),
                'iss' => 'localhost',
                'exp' => time() + 60 * 60 * 60,
                'userId' => $user->id
            ], self::JWT_SECRET_KEY);
        } catch (\Exception $e) {
            $this->throwError(500, 'Token Not Generate Please Try Again');
        }

    }

    public function getPayload()
    {
        $bearer = $this->request->getAuthCredentialsWithBearer();
        if (empty($bearer)){
            $this->throwError(203, 'Not set Token');
        }
        try {
            $payload = JWT::decode($bearer, self::JWT_SECRET_KEY, ['HS256']);
        }catch (\Exception $e){
            $this->throwError(401, 'Invalid Token');
        }

        return $payload;

    }
    public function checkTokenExpire($tokenTime , $changeTime){
        if ($tokenTime < strtotime($changeTime)){
            $this->throwError(401, 'Expire token');
        }
    }
}
