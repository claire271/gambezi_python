import websocket
import threading
import struct
import time

################################################################################
class Gambezi:
    """Represents a connection to a gambezi server"""

    def __init__(self, host_address, reconnect=False, reconnect_interval=5):
        """Constructs a gambezi instance with the given target host"""
        # Callbacks
        self.on_ready = None
        self.on_error = None
        self.on_close = None

        # Variables
        self.__key_request_queue = None
        self.__root_node = None
        self.__refresh_rate = None
        self.__host_address = None
        self.__ready = None
        self.__websocket = None

        # Init
        self.__root_node = Node("", None, self)
        self.__refresh_rate = 100
        self.__host_address = host_address

        self.open_connection()

        if reconnect:
            def reconnect_handler():
                while True:
                    time.sleep(reconnect_interval)
                    self.open_connection()
            thread = threading.Thread(target = reconnect_handler)
            thread.start()

    def open_connection(self):
        """Connects this gambezi instance to the server"""
        # Bail if the connection is still open
        if self.__ready:
            return 1

        # Clear queue
        self.__key_request_queue = []

        # Set flags
        self.__ready = False

        # Mark all nodes as not ready to communicate
        self.__unready_nodes(self.__root_node)

        # Websocket init
        def init():
            self.__websocket = websocket.WebSocketApp(
                "ws://" + self.__host_address,
                on_message = self.__on_message,
                on_error = self.__on_error,
                on_open = self.__on_open,
                on_close = self.__on_close,
                subprotocols = ["gambezi-protocol"])
            self.__websocket.run_forever()
        thread = threading.Thread(target = init)
        thread.start()

        # Success
        return 0

    def __on_error(self, ws, error):
        """Callback when there is a websocket error"""
        if self.on_error is not None:
            self.on_error(ws, error)

    def __on_open(self, ws):
        """Callback when websockets get initialized"""
        # Set is ready state
        self.__ready = True

        # Set refresh rate
        self.set_refresh_rate(self.__refresh_rate)

        # Queue all IDs for all nodes
        self.__queue_id_requests(self.__root_node, None)

        # Get the next queued ID request
        self.__process_key_request_queue()

        # Set root node
        self.__root_node._set_ready(True)

        # Notify of ready state
        if self.on_ready is not None:
            self.on_ready(ws)

    def __queue_id_requests(self, node, parent_string_key):
        """Recursive method to fetch all IDs for all nodes"""
        # Normal node
        if parent_string_key is not None:
            string_key = list(parent_string_key)
            string_key.append(node.get_name())
            self.__key_request_queue.append(string_key)
        # Root node
        else:
            string_key = []

        # Process children
        for child in node.get_children():
            self.__queue_id_requests(child, string_key)

    def __unready_nodes(self, node):
        """Recursive method to set all child nodes to not ready"""
        # Set node state
        node._set_ready(False)

        # Process children
        for child in node.get_children():
            self.__unready_nodes(child)

    def __on_close(self, ws):
        """Callback when websockets is closed"""
        self.__ready = False

        # Mark all nodes as not ready to communicate
        self.__unready_nodes(self.__root_node)

        # Notify of closed state
        if self.on_close is not None:
            self.on_close(ws)

    def __on_message(self, ws, buf):
        """Callback when the client recieves a packet from the server"""

        ########################################
        # ID response from server
        if buf[0] == 0:
            # Extract binary key
            binary_key = bytearray(buf[1])
            for i in range(len(binary_key)):
                binary_key[i] = buf[i + 2]

            # Extract name
            name_length = buf[len(binary_key) + 2]
            name_offset = len(binary_key) + 3
            name = buf[name_offset:name_offset+name_length].decode()

            # Bail if the root node got requested
            if len(binary_key) == 0:
                # Get the next queued ID request
                self.__process_key_request_queue()
                return

            # Get the matching node and set the ID
            node = self.__node_traverse(binary_key, True)
            # No error
            if node is not None:
                node = node.get_child_with_name(name, True)
                node._set_key(binary_key)

                # Get the next queued ID request
                self.__process_key_request_queue()

        ########################################
        # Value update from server
        elif buf[0] == 1:
            # Extract binary key
            binary_key = bytearray(buf[1])
            for i in range(len(binary_key)):
                binary_key[i] = buf[i + 2]

            # Extract data
            data_length = (buf[len(binary_key) + 2] << 8) | (buf[len(binary_key) + 3])
            data = bytearray(data_length)
            for i in range(data_length):
                data[i] = buf[len(binary_key) + 4 + i]

            # Get the matching node and set the data
            node = self.__node_traverse(binary_key, False)
            # No error
            if node is not None:
                node._set_data(data)

                # Callback if present
                if node.on_update is not None:
                    node.on_update(node)

        ########################################
        # Error message from server
        elif buf[0] == 2:
            # Extract buf
            message = buf[2:2+buf[1]].decode()
            # Use the message
            if self.on_error is not None:
                self.on_error(message)

    def is_ready(self):
        """Returns whether this gambezi instance is ready to communicate"""
        return self.__ready

    def close_connection(self):
        """Closes this gambezi connection"""
        if self.__websocket is not None:
            self.__websocket.close()

    def _request_id(self, parent_key, name, get_children=False, get_children_all=False):
        """
        Requests the ID of a node for a given parent key and name
        get_children determines if all descendent keys will be retrieved
        """
        # This method is always guarded when called, so no need to check readiness

        # Create buffer
        name_bytes = name.encode()
        buf = bytearray(len(parent_key) + len(name_bytes) + 4)

        # Header
        buf[0] = 0x00;
        buf[1] = (2 if get_children_all else 0) | (1 if get_children else 0)

        # Parent key
        buf[2] = len(parent_key)
        for i in range(len(parent_key)):
            buf[i + 3] = parent_key[i]

        # Name
        buf[3 + len(parent_key)] = len(name_bytes)
        for i in range(len(name_bytes)):
            buf[i + 4 + len(parent_key)] = name_bytes[i]

        # Send data
        self.__websocket.send(buf, opcode=websocket.ABNF.OPCODE_BINARY)

    def __process_key_request_queue(self):
        """Processes string key requests in the queue until one succeeds"""
        # This method is always guarded when called, so no need to check readiness

        # Process entries until one succeeds without an error
        while len(self.__key_request_queue) > 0:
            code = 0

            # Build the binary parent key
            string_key = self.__key_request_queue.pop(0)
            parent_binary_key = [0] * (len(string_key) - 1)
            node = self.__root_node
            for i in range(len(string_key) - 1):
                node = node.get_child_with_name(string_key[i], True)
                ident = node.get_id()
                # Bail if the parent does not have an ID
                if ident < 0:
                    code = 1
                    break
                parent_binary_key[i] = ident

            # Error when building binary key
            if code > 0:
                if self.on_error is not None:
                    self.on_error("Error processing ID queue")
            # No error
            else:
                # Request the ID
                name = string_key[-1]
                self._request_id(parent_binary_key, name, False, False)
                break;

    def register_key(self, string_key):
        """Registers a string key and gets the corresponding node"""
        # Queue up the ID requests and the node
        node = self.__root_node
        for i in range(len(string_key)):
            # Go down one level
            node = node.get_child_with_name(string_key[i], True)

            # Queue up ID request if needed
            if self.__ready:
                if node.get_id() < 0:
                    self.__key_request_queue.append(string_key[:i+1])

        # Get any IDs necessary
        if self.__ready:
            self.__process_key_request_queue()

        # Return
        return node

    def set_refresh_rate(self, refresh_rate):
        """Sets the refresh rate of this client in milliseconds"""
        # Save for later usage
        self.__refresh_rate = refresh_rate

        if self.__ready:
            # Create buffer
            buf = bytearray(3)

            # Header
            buf[0] = 0x02

            # Length
            buf[1] = (refresh_rate >> 8) & 0xFF
            buf[2] = (refresh_rate) & 0xFF

            # Send packet
            self.__websocket.send(buf, opcode=websocket.ABNF.OPCODE_BINARY)
            return 0
        else:
            return 1

    def get_refresh_rate(self):
        """Gets the refresh rate of this client in milliseconds"""
        return self.__refresh_rate

    def _set_data_raw(self, key, data, offset, length):
        """Sets the value of the node with a byte buffer"""
        # This method is always guarded when called, so no need to check readiness

        # Create buffer
        buf = bytearray(len(key) + length + 4)

        # Header
        buf[0] = 0x01

        # Key
        buf[1] = len(key)
        for i in range(len(key)):
            buf[i + 2] = key[i]

        # Length
        buf[2 + len(key)] = (length >> 8) & 0xFF
        buf[3 + len(key)] = (length) & 0xFF

        # Value
        for i in range(length):
            buf[i + 4 + len(key)] = data[i + offset]

        # Send packet
        self.__websocket.send(buf, opcode=websocket.ABNF.OPCODE_BINARY)

    def _request_data(self, key, get_children=False):
        """
        Requests the value of a node
        get_children determines if all descendent keys will be retrieved
        """
        # This method is always guarded when called, so no need to check readiness

        # Create buffer
        buf = bytearray(len(key) + 3)

        # Header
        buf[0] = 0x04
        buf[1] = 1 if get_children else 0

        # Key
        buf[2] = len(key)
        for i in range(len(key)):
            buf[i + 3] = key[i]

        # Send packet
        self.__websocket.send(buf, opcode=websocket.ABNF.OPCODE_BINARY)

    def _update_subscription(self, key, refresh_skip, set_children=False):
        """
        Updates the subscription for a paticular key
        set_children determines if all descendent keys will be retrieved

        Values for refresh_skip
        0x0000 - get node value updates as soon as they arrive
        0xFFFF - unsubscribe from this key
        Any other value of refresh skip indicates that this node will
        be nretrieved every n client updates
        """
        # This method is always guarded when called, so no need to check readiness

        # Create buffer
        buf = bytearray(len(key) + 5)

        # Header
        buf[0] = 0x03
        buf[1] = 1 if set_children else 0
        buf[2] = (refresh_skip >> 8) & 0xFF
        buf[3] = (refresh_skip) & 0xFF

        # Key
        buf[4] = len(key)
        for i in range(len(key)):
            buf[i + 5] = key[i]

        # Send packet
        self.__websocket.send(buf, opcode=websocket.ABNF.OPCODE_BINARY)

    def __node_traverse(self, binary_key, get_parent=False):
        """
        Gets the node for a given binary key
        get_parent determines if the immediate parent of the binary key
        will be retrieved instead
        """
        node = self.__root_node
        for i in range(len(binary_key) - (1 if get_parent else 0)):
            node = node._get_child_with_id(binary_key[i])
            # Bail if the key is bad
            if node is None:
                return None
        return node

################################################################################
class Node:
    """Represents a node in the Gambezi tree"""

    def __init__(self, name, parent_key, parent_gambezi):
        """
        Constructs a node with a given name, parent key, and parent gambezi
        If the parent key is null, the Node is constructed as the root node
        """
        # Callbacks
        self.on_ready = None
        self.on_update = None

        # Variables
        self.__name = None
        self.__gambezi = None
        self.__children = None
        self.__send_queue = None
        self.__refresh_skip = None
        self.__data = None
        self.__key = None
        self.__ready = None

        # Flags
        self.__ready = False

        self.__name = name
        self.__gambezi = parent_gambezi

        self.__children = []
        self.__send_queue = []

        self.__refresh_skip = 0xFFFF
        self.__data = b''

        # Init key
        self.__key = []
        if parent_key is not None:
            self.__key = list(parent_key)
            self.__key.append(-1)

    def get_children(self):
        """Gets a list of all currently visible child nodes"""
        return self.__children

    def get_id(self):
        """
        Gets the ID of this node.
        (-1) indicates no ID has been assigned yet.
        """
        return self.__key[-1]

    def get_name(self):
        """Gets the name of this node"""
        return self.__name

    def _set_key(self, key):
        """Sets the binary key of this node"""
        # Notify ready
        self.__key = key
        self._set_ready(True)

        # Handle queued actions
        while len(self.__send_queue) > 0:
            (self.__send_queue.pop(0))()

    def get_key(self):
        """Gets the binary key of this node"""
        return self.__key

    def _set_data(self, data):
        """Sets the data of this node"""
        self.__data = data

    def get_data(self):
        """Gets the data of this node"""
        return self.__data

    def _set_ready(self, ready):
        # Save state
        self.__ready = ready

        # Notify ready
        if ready:
            # Set refresh skip
            self.update_subscription(self.__refresh_skip)

            if self.on_ready is not None:
                self.on_ready()

    def is_ready(self):
        """Returns if this node is ready to communicate"""
        return self.__ready

    def get_child_with_name(self, name, create=False):
        """
        Gets the child node with the specified name
        Creates a new child name if there is no existing child
        """
        # See if child already exists
        for child in self.__children:
            if child.get_name() == name:
                return child

        # Bail if requested not to create
        if not create:
            return None

        # Create child if nonexistent
        child = Node(name, self.__key, self.__gambezi)
        self.__children.append(child)
        return child

    def _get_child_with_id(self, ident):
        """
        Gets the child node with the specified ID
        Returns null if the ID is not found
        """
        # See if the child already exists
        for child in self.__children:
            if child.get_id() == ident:
                return child

        # None found
        return None

    def set_data_raw(self, data, offset, length):
        """Sets the value of a node"""
        if self.__ready:
            self.__gambezi._set_data_raw(self.__key, data, offset, length)
            return 0
        else:
            self.__send_queue.append(lambda: self.set_data_raw(data, offset, length))
            return 1

    def request_data(self, get_children=False):
        """
        Requests the value of a node
        get_children determines if all descendent keys will be retrieved
        """
        if self.__ready:
            self.__gambezi._request_data(self.__key, get_children)
            return 0
        else:
            self.__send_queue.append(lambda: self.request_data(get_children))
            return 1
        
    def update_subscription(self, refresh_skip, set_children=False):
        """
        Updates the subscription for this node
        set_children determines if all descendent keys will be retrieved

        Values for refresh_skip
        0x0000 - get node value updates as soon as they arrive
        0xFFFF - unsubscribe from this key
        Any other value of refresh skip indicates that this node will be
        retrieved every n client updates
        """
        # Save for later usage
        self.__refresh_skip = refresh_skip

        if self.__ready:
            self.__gambezi._update_subscription(self.__key, refresh_skip, set_children)
            return 0
        else:
            return 1

    def retrieve_children(self):
        """Retrieves all immediate children of this node from the server"""
        if self.__ready:
            self.__gambezi._request_id(self.__key, "", True, False)
            return 0
        else:
            self.__send_queue.append(lambda: self.retrieve_children())
            return 1

    def retrieve_children_all(self):
        """Retrieves all children of this node from the server"""
        if self.__ready:
            self.__gambezi._request_id(self.__key, "", True, True)
            return 0
        else:
            self.__send_queue.append(lambda: self.retrieve_children_all())
            return 1

    def set_float(self, value):
        """Sets the value of the node as a 32 bit float"""
        return self.set_data_raw(struct.pack("!f", value), 0, 4)

    def get_float(self):
        """
        Gets the value of this node as a 32 bit float
        Returns NaN as the default if the format does not match
        """
        # Bail if the size is incorrect
        if len(self.__data) != 4:
            return float('nan')
        # Size is correct
        return struct.unpack("!f", self.__data)[0]

    def set_boolean(self, value):
        """Sets the value of the node as a boolean"""
        return self.set_data_raw(b'\x01' if value else b'\x00', 0, 1)

    def get_boolean(self):
        """
        Gets the value of this node as a boolean
        Returns false as the default if the format does not match
        """
        # Bail if the size is incorrect
        if len(self.__data) != 1:
            return False
        # Size is correct
        return self.__data[0] != 0x00

    def set_string(self, value):
        """Sets the value of the node as a string"""
        value_bytes = value.encode()
        return self.set_data_raw(value_bytes, 0, len(value_bytes))

    def get_string(self):
        """Gets the value of this node as a string"""
        return self.__data.decode()

