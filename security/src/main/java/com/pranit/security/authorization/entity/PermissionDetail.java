package com.pranit.security.authorization.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.UUID;

@Entity
@Table(
        name = "permission_detail",
        schema = "authorization_schema",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_permission_detail_code", columnNames = "permission_code"
                )
        },
        indexes = {
                @Index(
                        name = "idx_permission_detail_code", columnList = "permission_code"
                ),
                @Index(
                        name = "idx_permission_detail_deleted", columnList = "deleted"
                )
        }
)
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class PermissionDetail implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "permission_id", nullable = false, updatable = false)
    private UUID permissionId;

    @Column(name = "permission_code", nullable = false, length = 100)
    private String permissionCode;

    @Column(name = "permission_description", length = 500)
    private String permissionDescription;

    @Column(name = "deleted", nullable = false)
    @Builder.Default
    private boolean deleted = false;

    @Version
    private long version;
}
