#!/bin/bash
direnv allow .
mimirtool alertmanager load <(envsubst <alertmanager.yml)
