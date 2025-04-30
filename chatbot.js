// Webo Chatbot Implementation
document.addEventListener("DOMContentLoaded", function () {
  // Create and append chatbot elements to the DOM
  createChatbotElements();

  // Initialize chatbot state and event handlers
  initChatbot();
});

// Create all necessary HTML elements for the chatbot
function createChatbotElements() {
  // Create chatbot launcher (icon button)
  const launcher = document.createElement("div");
  launcher.className = "chatbot-launcher";
  launcher.id = "chatbot-launcher";
  launcher.innerHTML = '<i class="fas fa-comment-dots"></i>';
  document.body.appendChild(launcher);

  // Create chatbot container
  const container = document.createElement("div");
  container.className = "chatbot-container chatbot-minimized";
  container.id = "chatbot-container";

  // Create header
  const header = document.createElement("div");
  header.className = "chatbot-header";
  header.innerHTML = `
        <h3><i class="fas fa-shield-alt"></i> Webo Security Assistant</h3>
        <button id="chatbot-toggle" class="chatbot-toggle"><i class="fas fa-minus"></i></button>
    `;

  // Create body
  const body = document.createElement("div");
  body.className = "chatbot-body";

  // Create messages container
  const messagesDiv = document.createElement("div");
  messagesDiv.className = "chatbot-messages";
  messagesDiv.id = "chatbot-messages";

  // Create input area
  const inputDiv = document.createElement("div");
  inputDiv.className = "chatbot-input";
  inputDiv.innerHTML = `
        <input type="text" class="chat-input-field" id="chat-input" placeholder="Ask about web security..." />
        <button class="chat-send-btn" id="chat-send-btn">
            <i class="fas fa-paper-plane"></i>
        </button>
    `;

  // Assemble all components
  body.appendChild(messagesDiv);
  body.appendChild(inputDiv);
  container.appendChild(header);
  container.appendChild(body);
  document.body.appendChild(container);
}

// Initialize chatbot functionality
function initChatbot() {
  const chatbotLauncher = document.getElementById("chatbot-launcher");
  const chatbotContainer = document.getElementById("chatbot-container");
  const chatbotToggle = document.getElementById("chatbot-toggle");
  const chatInput = document.getElementById("chat-input");
  const sendButton = document.getElementById("chat-send-btn");
  const messagesContainer = document.getElementById("chatbot-messages");

  // Add welcome message
  addBotMessage(
    "Hello! I'm Webo, your security assistant. How can I help you with web security today?"
  );

  // Toggle chatbot visibility when launcher is clicked
  chatbotLauncher.addEventListener("click", function () {
    chatbotLauncher.classList.add("hidden");
    chatbotContainer.classList.remove("chatbot-minimized");
    chatbotContainer.classList.add("expanded");
    chatInput.focus();
  });

  // Toggle chatbot minimize/maximize
  chatbotToggle.addEventListener("click", function () {
    if (chatbotContainer.classList.contains("expanded")) {
      // Minimize
      chatbotContainer.classList.remove("expanded");
      chatbotLauncher.classList.remove("hidden");
      chatbotToggle.innerHTML = '<i class="fas fa-plus"></i>';
    } else {
      // Maximize
      chatbotContainer.classList.add("expanded");
      chatbotLauncher.classList.add("hidden");
      chatbotToggle.innerHTML = '<i class="fas fa-minus"></i>';
      chatInput.focus();
    }
  });

  // Send message on button click
  sendButton.addEventListener("click", sendMessage);

  // Send message on Enter key
  chatInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
      sendMessage();
    }
  });

  // Function to send message
  function sendMessage() {
    const message = chatInput.value.trim();
    if (message.length === 0) return;

    // Add user message to chat
    addUserMessage(message);

    // Clear input
    chatInput.value = "";

    // Show typing indicator
    showTypingIndicator();

    // Send message to backend
    fetch("/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: message }),
    })
      .then((response) => response.json())
      .then((data) => {
        // Remove typing indicator
        hideTypingIndicator();

        // Add bot response
        addBotMessage(data.message, !data.is_security_related);

        // Scroll to bottom
        scrollToBottom();
      })
      .catch((error) => {
        // Remove typing indicator
        hideTypingIndicator();

        // Show error message
        addBotMessage(
          "Sorry, I'm having trouble connecting right now. Please try again later."
        );
        console.error("Error:", error);

        // Scroll to bottom
        scrollToBottom();
      });
  }

  // Add user message to chat
  function addUserMessage(message) {
    const messageDiv = document.createElement("div");
    messageDiv.className = "chat-message user-message";
    messageDiv.innerHTML = `
            <div class="chat-avatar user-avatar">U</div>
            <div class="message-content">${escapeHtml(message)}</div>
        `;
    messagesContainer.appendChild(messageDiv);
    scrollToBottom();
  }

  // Add bot message to chat
  function addBotMessage(message, isNotSecurityRelated = false) {
    const messageDiv = document.createElement("div");
    messageDiv.className = "chat-message bot-message";

    // Convert markdown-like syntax to HTML (simple version)
    const formattedMessage = formatMessage(message);

    const contentClass = isNotSecurityRelated
      ? "message-content not-security-related"
      : "message-content";

    messageDiv.innerHTML = `
            <div class="chat-avatar bot-avatar">W</div>
            <div class="${contentClass}">${formattedMessage}</div>
        `;
    messagesContainer.appendChild(messageDiv);
    scrollToBottom();
  }

  // Show typing indicator
  function showTypingIndicator() {
    const typingDiv = document.createElement("div");
    typingDiv.className = "chatbot-typing";
    typingDiv.id = "typing-indicator";
    typingDiv.innerHTML = `
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
        `;
    messagesContainer.appendChild(typingDiv);
    scrollToBottom();
  }

  // Hide typing indicator
  function hideTypingIndicator() {
    const typingIndicator = document.getElementById("typing-indicator");
    if (typingIndicator) {
      typingIndicator.remove();
    }
  }

  // Scroll messages container to bottom
  function scrollToBottom() {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  // Format message with simple markdown support
  function formatMessage(message) {
    if (!message) return "";

    // Escape HTML first to prevent XSS
    let formatted = escapeHtml(message);

    // Simple markdown-like formatting
    // Bold
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");

    // Italic
    formatted = formatted.replace(/\*(.*?)\*/g, "<em>$1</em>");

    // Code
    formatted = formatted.replace(/`(.*?)`/g, "<code>$1</code>");

    // Convert line breaks to <br>
    formatted = formatted.replace(/\n/g, "<br>");

    return formatted;
  }

  // Escape HTML to prevent XSS
  function escapeHtml(unsafe) {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}
