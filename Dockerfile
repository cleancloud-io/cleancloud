FROM python:3.13-alpine

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apk update && apk upgrade && rm -rf /var/cache/apk/* \
    && pip install --upgrade pip

ARG CLEANCLOUD_VERSION
RUN if [ -n "${CLEANCLOUD_VERSION}" ]; then \
        pip install cleancloud==${CLEANCLOUD_VERSION}; \
    else \
        pip install cleancloud; \
    fi

ENTRYPOINT ["cleancloud"]
