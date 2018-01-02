import websocket
import threading
import struct
import time

################################################################################
class Gambezi:
    """Represents a connection to a gambezi server"""
################################################################################

    #-------------------------------------------------------------------------------
    def __init__(self, host_address, reconnect=True, reconnect_interval=5):
        """Constructs a gambezi instance with the given target host"""
        # Callbacks
        self.on_ready = None
        self.on_error = None
        self.on_close = None
    
        # Variables
        self.__key_request_queue    = None
        self.__root_node            = None
        self.__refresh_rate         = 0
        self.__host_address         = None
        self.__ready                = False
        self.__websocket            = None
        self.__default_subscription = 0
        self.__reconnect            = False
        self.__reconnect_interval   = 0
        self.__heartbeat            = False
    
        # Init
        self.__root_node = _Node(None, None, self)
        self.__refresh_rate = 100
        self.__host_address = host_address
        self.__default_subscription = 1
        self.__reconnect = reconnect
        self.__reconnect_interval = reconnect_interval
        self.__heartbeat = True
    
        # Attempt to open connection
        self.open_connection()

        # Setup heartbeat
        self.__root_node.set_subscription(round(self.__reconnect_interval * 1000 / self.__refresh_rate / 2))
        def root_node_on_update(node):
            self.__heartbeat = True
        self.__root_node.on_update = root_node_on_update

        # Heartbeat monitoring
        def heartbeat_monitor():
            while True:
                # Limit rate
                time.sleep(reconnect_interval)

                # Heartbeat not found
                if not self.__heartbeat:
                    self.close_connection()

                    # Reopen if requested to
                    if reconnect:
                        self.open_connection()

                # Clear heartbeat
                self.__heartbeat = False
        thread = threading.Thread(target = heartbeat_monitor)
        thread.start()

    #===============================================================================
    # Gambezi client methods
    #===============================================================================

    #-------------------------------------------------------------------------------
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

    #-------------------------------------------------------------------------------
    def close_connection(self):
        """Closes this gambezi connection"""
        if self.__websocket is not None:
            self.__websocket.close()

    #-------------------------------------------------------------------------------
    def get_ready(self):
        """Returns whether this gambezi instance is ready to communicate"""
        return self.__ready

    #-------------------------------------------------------------------------------
    def set_refresh_rate(self, refresh_rate):
        """Sets the refresh rate of this client in milliseconds"""
        # Save for later usage
        self.__refresh_rate = refresh_rate

        # Update heartbeat
        self.__root_node.set_subscription(round(self.__reconnect_interval * 1000 / self.__refresh_rate / 2))

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

    #-------------------------------------------------------------------------------
    def get_refresh_rate(self):
        """Gets the refresh rate of this client in milliseconds"""
        return self.__refresh_rate

    #-------------------------------------------------------------------------------
    def set_default_subscription(self, default_subscription):
        """
        Sets the default subscription rate for this client. Changes are not applied
        retroactively
        """
        self.__default_subscription = default_subscription

    #-------------------------------------------------------------------------------
    def get_default_subscription(self):
        """Gets the default subscription rate for this client"""
        return self.__default_subscription

    #===============================================================================
    # Tree information methods
    #===============================================================================

    #-------------------------------------------------------------------------------
    def get_node(self, string_key, delimiter="/", parent_node=None):
        """
        Gets a node with the given name as a child of the given node.
        
        If string_key is a string array, each element of the array is considered a
        level in the tree. If string_key is a single string, the string is split by
        the delimiter and each resulting element is considered a level in the tree.
        
        If parent_node is not given, the key is referenced from the root node.
        """
        # Handle the case of the root node
        if parent_node is None:
            parent_node = self.__root_node

        # Split string_key if necessary
        if not isinstance(string_key, list):
            string_key = string_key.split(delimiter)

        # Request node
        return self.__request_node(parent_node.get_string_key() + string_key)

    #-------------------------------------------------------------------------------
    def get_root_node():
        """Gets the root node"""
        return self.__root_node

    #-------------------------------------------------------------------------------
    def __request_node(self, string_key):
        """Registers a string key and gets the corresponding node"""
        # Queue up the ID requests and the node
        node = self.__root_node
        for i in range(len(string_key)):
            # Go down one level
            node = node._get_child_with_name(string_key[i])

            # Queue up ID request if needed
            if self.__ready:
                if node.get_id() < 0:
                    self.__key_request_queue.append(string_key[:i+1])

        # Get any IDs necessary
        if self.__ready:
            self.__process_key_request_queue()

        # Return
        return node

    #-------------------------------------------------------------------------------
    def _request_id(self, parent_key, name, get_children, get_children_all):
        """
        Requests the ID of a node for a given parent key and name

        get_children determines if all descendent keys will be retrieved

        get_children_all determines if all descendent keys will be retrieved
        recursively
        """
        # This method is always guarded when called, so no need to check readiness

        # Create buffer
        name_bytes = name.encode()
        buf = bytearray(len(parent_key) + len(name_bytes) + 4)

        # Header
        buf[0] = 0x00
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

    #-------------------------------------------------------------------------------
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
                node = node._get_child_with_name(string_key[i])
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
                break

    #-------------------------------------------------------------------------------
    def __queue_id_requests(self, node, parent_string_key):
        """Recursive method to fetch all IDs for all nodes"""
        # Normal node
        if parent_string_key is not None:
            string_key = parent_string_key.copy()
            string_key.append(node.get_name())
            self.__key_request_queue.append(string_key)
        # Root node
        else:
            string_key = []

        # Process children
        for child in node.get_children():
            self.__queue_id_requests(child, string_key)

    #-------------------------------------------------------------------------------
    def __unready_nodes(self, node):
        """Recursive method to set all child nodes to not ready"""
        # Set node state
        node._set_ready(False)

        # Process children
        for child in node.get_children():
            self.__unready_nodes(child)

    #-------------------------------------------------------------------------------
    def __traverse_tree(self, binary_key, get_parent):
        """
        Gets the node for a given binary key

        get_parent determines if the immediate parent of the binary key will be
        retrieved instead
        """
        node = self.__root_node
        for i in range(len(binary_key) - (1 if get_parent else 0)):
            node = node._get_child_with_id(binary_key[i])
            # Bail if the key is bad
            if node is None:
                return None
        return node

    #===============================================================================
    # Individual node methods
    #===============================================================================

    #-------------------------------------------------------------------------------
    def _request_data(self, key, get_children):
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

    #-------------------------------------------------------------------------------
    def _set_data(self, key, data, offset, length):
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

    #-------------------------------------------------------------------------------
    def _set_subscription(self, key, refresh_skip, set_children):
        """
        Updates the subscription for a paticular key

        set_children determines if all descendent keys will be retrieved

        Values for refresh_skip
        0x0000 - get node value updates as soon as they arrive
        0xFFFF - unsubscribe from this key
        Any other value of refresh skip indicates that this node will be retrieved
        every n client updates
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

    #===============================================================================
    # Gambezi to websocket callbacks
    #===============================================================================

    #-------------------------------------------------------------------------------
    def __on_error(self, ws, error):
        """Callback when there is a websocket error"""
        if self.on_error is not None:
            self.on_error(error)

    #-------------------------------------------------------------------------------
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

    #-------------------------------------------------------------------------------
    def __on_close(self, ws):
        """Callback when websockets is closed"""
        self.__ready = False

        # Mark all nodes as not ready to communicate
        self.__unready_nodes(self.__root_node)

        # Notify of closed state
        if self.on_close is not None:
            self.on_close(ws)

    #-------------------------------------------------------------------------------
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
            node = self.__traverse_tree(binary_key, True)
            # No error
            if node is not None:
                node = node._get_child_with_name(name)
                node._set_binary_key(binary_key)

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
            node = self.__traverse_tree(binary_key, False)
            # No error
            if node is not None:
                node._data_received(data)

        ########################################
        # Error message from server
        elif buf[0] == 2:
            # Extract buf
            message = buf[2:2+buf[1]].decode()
            # Use the message
            if self.on_error is not None:
                self.on_error(message)

################################################################################
class _Node:
    """Represents a node in the Gambezi tree"""
################################################################################

    #-------------------------------------------------------------------------------
    def __init__(self, name, parent_node, parent_gambezi):
        """
        Constructs a node with a given name, parent node, and parent gambezi
        If the parent node is null, the Node is constructed as the root node
        """
        # Callbacks
        self.on_ready = None
        self.on_update = None

        # Variables
        self.__parent       = None
        self.__gambezi      = None
        self.__children     = None
        self.__send_queue   = None
        self.__refresh_skip = 0
        self.__data         = None
        self.__binary_key   = None
        self.__string_key   = None
        self.__ready        = False

        # Flags
        self.__ready = False

        self.__parent = parent_node
        self.__gambezi = parent_gambezi

        self.__children = []
        self.__send_queue = []

        self.__refresh_skip = parent_gambezi.get_default_subscription()
        self.__data = b''

        # Init key
        self.__binary_key = []
        self.__string_key = []
        if parent_node is not None:
            self.__binary_key = parent_node.__binary_key.copy()
            self.__binary_key.append(-1)
            self.__string_key = parent_node.__string_key.copy()
            self.__string_key.append(name)

    #===============================================================================
    # Node information methods
    #===============================================================================

    #-------------------------------------------------------------------------------
    def _set_binary_key(self, key):
        """Sets the binary key of this node"""
        # Notify ready
        self.__binary_key = key
        self._set_ready(True)

        # Handle queued actions
        while len(self.__send_queue) > 0:
            (self.__send_queue.pop(0))()

    #-------------------------------------------------------------------------------
    def get_binary_key(self):
        """Gets the binary key of this node"""
        return self.__binary_key

    #-------------------------------------------------------------------------------
    def get_id(self):
        """
        Gets the ID of this node
        (-1) indicates no ID has been assigned yet.
        """
        if self.__parent is not None:
            return self.__binary_key[-1]
        else:
            return 0

    #-------------------------------------------------------------------------------
    def get_string_key(self):
        """Gets the string key of this node"""
        return self.__string_key

    #-------------------------------------------------------------------------------
    def get_name(self):
        """Gets the name of this node"""
        if self.__parent is not None:
            return self.__string_key[-1]
        else:
            return ""

    #-------------------------------------------------------------------------------
    def get_parent():
        """Gets the parent of this node"""
        return self.__parent

    #-------------------------------------------------------------------------------
    def _set_ready(self, ready):
        """Sets the ready state of this node"""
        # Save state
        self.__ready = ready

        # Notify ready
        if ready:
            # Set refresh skip
            self.set_subscription(self.__refresh_skip)

            if self.on_ready is not None:
                self.on_ready(self)

    #-------------------------------------------------------------------------------
    def get_ready(self):
        """Returns if this node is ready to communicate"""
        return self.__ready

    #-------------------------------------------------------------------------------
    def set_subscription(self, refresh_skip, set_children=False):
        """
        Updates the subscription for this node

        set_children determines if all descendent keys will be retrieved

        Values for refresh_skip
        0x0000 - get node value updates as soon as they arrive
        0xFFFF - unsubscribe from this key
        Any other value of refresh skip indicates that this node will be retrieved
        every n client updates
        """
        # Save for later usage
        self.__refresh_skip = refresh_skip

        if self.__ready:
            self.__gambezi._set_subscription(self.__binary_key, refresh_skip, set_children)
            return 0
        else:
            return 1

    #-------------------------------------------------------------------------------
    def get_subscription():
        """Gets the current subscription of this node"""
        return self.__refresh_skip

    #===============================================================================
    # Tree information methods
    #===============================================================================

    #-------------------------------------------------------------------------------
    def get_node(self, string_key, delimiter="/"):
        """
        Gets a node with the given name as a child of the given node.
        
        If string_key is a string array, each element of the array is considered a
        level in the tree. If string_key is a single string, the string is split by
        the delimiter and each resulting element is considered a level in the tree.
        
        The node being retrieved will be referenced from the current node
        """
        return self.__gambezi.get_node(string_key, delimiter, self)

    #-------------------------------------------------------------------------------
    def request_children(self):
        """Retrieves all immediate children of this node from the server"""
        if self.__ready:
            self.__gambezi._request_id(self.__key, "", True, False)
            return 0
        else:
            self.__send_queue.append(lambda: self.request_children())
            return 1

    #-------------------------------------------------------------------------------
    def request_all_children(self):
        """Retrieves all children of this node from the server"""
        if self.__ready:
            self.__gambezi._request_id(self.__key, "", True, True)
            return 0
        else:
            self.__send_queue.append(lambda: self.request_all_children())
            return 1

    #-------------------------------------------------------------------------------
    def get_children(self):
        """Gets all children currently visible to this node"""
        return self.__children

    #-------------------------------------------------------------------------------
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

    #-------------------------------------------------------------------------------
    def _get_child_with_name(self, name):
        """
        Gets the child node with the specified name
        Creates a new child name if there is no existing child
        """
        # See if child already exists
        for child in self.__children:
            if child.get_name() == name:
                return child

        # Create child if nonexistent
        child = _Node(name, self, self.__gambezi)
        self.__children.append(child)
        return child

    #===============================================================================
    # Data handling methods
    #===============================================================================

    #-------------------------------------------------------------------------------
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

    #-------------------------------------------------------------------------------
    def _data_received(self, data):
        """Data of this node received from server"""
        self.__data = data

        # Callback if present
        if self.on_update is not None:
            self.on_update(self)

    #-------------------------------------------------------------------------------
    def set_data(self, data, offset, length):
        """Sets the value of a node with a byte buffer"""
        if self.__ready:
            self.__gambezi._set_data(self.__key, data, offset, length)
            return 0
        else:
            self.__send_queue.append(lambda: self.set_data(data, offset, length))
            return 1

    #-------------------------------------------------------------------------------
    def get_data(self):
        """Gets the data of this node"""
        return self.__data

    #-------------------------------------------------------------------------------
    def set_double(self, value):
        """Sets the value of the node as a 64 bit float"""
        return self.set_data_raw(struct.pack("!d", value), 0, 8)

    #-------------------------------------------------------------------------------
    def get_double(self):
        """
        Gets the value of this node as a 64 bit float
        Returns NaN as the default if the format does not match
        """
        # Bail if the size is incorrect
        if len(self.__data) != 8:
            return float('nan')
        # Size is correct
        return struct.unpack("!d", self.__data)[0]

    #-------------------------------------------------------------------------------
    def set_float(self, value):
        """Sets the value of the node as a 32 bit float"""
        return self.set_data_raw(struct.pack("!f", value), 0, 4)

    #-------------------------------------------------------------------------------
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

    #-------------------------------------------------------------------------------
    def set_boolean(self, value):
        """Sets the value of the node as a boolean"""
        return self.set_data_raw(b'\x01' if value else b'\x00', 0, 1)

    #-------------------------------------------------------------------------------
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

    #-------------------------------------------------------------------------------
    def set_string(self, value):
        """Sets the value of the node as a string"""
        value_bytes = value.encode()
        return self.set_data_raw(value_bytes, 0, len(value_bytes))

    #-------------------------------------------------------------------------------
    def get_string(self):
        """Gets the value of this node as a string"""
        return self.__data.decode()
