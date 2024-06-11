import socket
import threading
import os
import sys
import logging
import re
import gzip

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

class HTTPServer:
    def __init__(self, host='localhost', port=4221):
        self.logger = logging.getLogger(__name__)
        self.host = host
        self.port = port
        self.server_socket = socket.create_server((self.host, self.port), reuse_port=True)
        self.response_handler = ResponseHandler()

    def run(self):
        self.logger.info(f"The server is running on {self.host}:{self.port}...")
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                self.logger.debug(f"Connection from {addr} has been established")
                threading.Thread(target=self.handle_request, args=(client_socket,)).start()
        except KeyboardInterrupt:
            self.logger.info("\nServer is shutting down...")
        finally:
            self.shutdown()
    
    def shutdown(self):
        self.server_socket.close()
        print("Server has been shut down.")

    def handle_request(self, client_socket):
        try:
            # Receive data from client:
            request_data = client_socket.recv(1024)
            if not request_data:
                self.logger.warning("No data received.")
                return
            
            header_part, _, initial_body_part = request_data.partition(b'\r\n\r\n')
            
            # Decode and parse request
            headers_text = header_part.decode('utf-8')
            method, path, version = headers_text.split('\r\n')[0].split()
            headers = {k.strip(): v.strip() for k, v in (line.split(':', 1) for line in headers_text.split('\r\n')[1:] if ':' in line)}

            # Determine content length
            content_length = int(headers.get('Content-Length', 0))

            # Read the body
            body = initial_body_part # Start with initial read
            # Read rest of the body if not fuly received yet
            while len(body) < content_length:
                body += client_socket.recv(content_length - len(body))

            # Process request through response handler
            response = self.response_handler.route_request(method, path, headers, body)
            
            # Send response
            client_socket.sendall(response)
        except Exception as e:
            self.logger.error(f"Error handling request", exc_info=True)
            client_socket.sendall(ResponseHandler.error_response(e))
        finally:
            client_socket.close()
            

class ResponseHandler:
    logger = logging.getLogger(__name__)

    @staticmethod
    def route_request(method, path, headers, body):
        ResponseHandler.logger.debug(f"Routing request: {method} {path}")
        routes = {
            r"^/$": ResponseHandler.handle_root,
            r"^/echo/.*": ResponseHandler.handle_echo,
            r"^/user-agent$": ResponseHandler.handle_user_agent,
            r"/files/.*": ResponseHandler.handle_post_files if method=='POST' else ResponseHandler.handle_files
        }

        for pattern, handler in routes.items():
            if re.match(pattern, path):
                ResponseHandler.logger.debug(f"Match found: {pattern} for path {path}")
                return handler(method, path, headers, body)
        
        ResponseHandler.logger.warning(f"No match found for path: {path}, returning default response")
        return ResponseHandler.default_response()
    
    @staticmethod
    def handle_root(method, path, headers, body):
        return "HTTP/1.1 200 OK\r\n\r\n".encode()
    
    @staticmethod
    def handle_echo(method, path, headers, body): 
        str_message = path[len("/echo/"):]
        # Check Accept-Encoding header
        encoding = headers.get('Accept-Encoding', '')
        
        # Prepare response headers
        response_headers = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/plain",
        ]

        # Encode message
        byte_message = str_message.encode()

        # Add content-encoding if accepted type
        if 'gzip' in encoding:
            response_headers.append("Content-Encoding: gzip")
            ResponseHandler.logger.debug("Encoding file with gzip")

            byte_message = gzip.compress(byte_message)
        
        response_headers.append(f"Content-Length: {len(byte_message)}")

        #Create response
        str_headers = "\r\n".join(response_headers) + "\r\n\r\n"
        byte_headers = str_headers.encode()
        response = byte_headers + byte_message
        ResponseHandler.logger.debug(f"Returning response: {response}")
        return response
    
    @staticmethod
    def handle_user_agent(method, path, headers, body):
        user_agent = headers.get("User-Agent", "Unknown")
        return f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(user_agent)}\r\n\r\n{user_agent}".encode()
    
    @staticmethod
    def handle_files(method, path, headers, body):
        base_directory = sys.argv[2] if len(sys.argv) > 2 else '/tmp'
        relative_path = path[len("/files/"):].strip()
        safe_path = os.path.join(base_directory, os.path.normpath(relative_path))
        if not safe_path.startswith(os.path.abspath(base_directory)):
            return "HTTP/1.1 403 Forbidden\r\n\r\nAccess denied.".encode()
        
        try:
            with open(safe_path, 'rb') as file:
                body = file.read()
            response_headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            )
            return response_headers.encode() + body
        except FileNotFoundError:
            return "HTTP/1.1 404 Not Found\r\n\r\nFile not found.".encode()
        except Exception as e:
            return ResponseHandler.error_response(e)
        
    @staticmethod
    def handle_post_files(method, path, headers, body):
        filename = path.split('/')[-1]
        base_directory = sys.argv[2] if len(sys.argv) > 2 else '/tmp'
        file_path = os.path.join(base_directory, filename)
        
        try:
            with open(file_path, 'wb') as file:
                file.write(body.encode if isinstance(body, str) else body)

            return "HTTP/1.1 201 Created\r\n\r\n".encode()
        except Exception as e:
            logging.error(f"Failed to write to file: {e}")
            return ResponseHandler.error_response(e)

    @staticmethod
    def default_response():
        return "HTTP/1.1 404 Not Found\r\n\r\nResource not found".encode()
    
    @staticmethod
    def error_response(e):
        return f"HTTP/1.1 500 Internal Server Error\r\n\r\n{str(e)}".encode()
    

def main():
    server = HTTPServer()
    server.run()

if __name__ == "__main__":
    main()
