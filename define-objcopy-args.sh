#!/bin/sh

set -eu

while read REPLY
do
    case ${REPLY} in
        'using internal linker script:'*)
            read _
            break
            ;;
    esac
done

while read REPLY
do
    case ${REPLY} in
        'OUTPUT_FORMAT('*)
            OUTPUT_FORMAT=${REPLY#'OUTPUT_FORMAT("'}
            OUTPUT_FORMAT=${OUTPUT_FORMAT%%'"'*}
            echo "--output-format=${OUTPUT_FORMAT}"
            ;;
        'OUTPUT_ARCH('*)
            OUTPUT_ARCH=${REPLY#'OUTPUT_ARCH('}
            OUTPUT_ARCH=${OUTPUT_ARCH%%')'*}
            echo "--binary-architecture=${OUTPUT_ARCH}"
            ;;
    esac
done
