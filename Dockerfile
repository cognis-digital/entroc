# Multi-stage build: compile with gcc, ship a tiny runtime image.
FROM gcc:13 AS build
WORKDIR /src
COPY entroc.c .
RUN mkdir -p /out && \
    gcc -O2 -std=c99 -Wall -Wextra -Werror -o /out/entroc entroc.c -lm

FROM debian:bookworm-slim
COPY --from=build /out/entroc /usr/local/bin/entroc
# libm/libc come from the base image; entroc has no other runtime deps.
ENTRYPOINT ["entroc"]
CMD ["--help"]
