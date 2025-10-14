# Makefile

CC      = gcc
CFLAGS  = -Wall -Wextra -Werror
SRC_DIR = sources
OBJ_DIR = objects

SRC     = $(wildcard $(SRC_DIR)/*.c)
OBJ     = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC))
HEADERS = $(wildcard $(INC_DIR)/*.h)

TARGET  = woody_woodpacker

all: $(TARGET)

$(TARGET): $(OBJ) $(HEADERS)
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(TARGET)

re: fclean all

.PHONY: all clean fclean re
