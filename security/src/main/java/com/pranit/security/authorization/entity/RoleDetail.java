package com.pranit.security.authorization.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.modulith.NamedInterface;

import java.io.Serial;
import java.io.Serializable;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(
        name = "role_detail",
        schema = "authorization_schema",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_role_detail_name", columnNames = "role_name"
                )
        },
        indexes = {
                @Index(
                        name = "idx_role_detail_name", columnList = "role_name"
                ),
                @Index(
                        name = "idx_role_detail_deleted", columnList = "deleted"
                )
        }
)
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@NamedInterface("role")
public class RoleDetail implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "role_id", nullable = false, updatable = false)
    private UUID roleId;

    @Column(name = "role_name", nullable = false, length = 100)
    private String roleName;

    @Column(name = "role_description", length = 500)
    private String roleDescription;

    @Column(name = "deleted", nullable = false)
    @Builder.Default
    private boolean deleted = false;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "role_permissions",
            schema = "authorization_schema",
            joinColumns = @JoinColumn(
                    name = "role_id",
                    referencedColumnName = "role_id",
                    foreignKey = @ForeignKey(name = "fk_role_permission_role")
            ),
            inverseJoinColumns = @JoinColumn(
                    name = "permission_id",
                    referencedColumnName = "permission_id",
                    foreignKey = @ForeignKey(name = "fk_role_permission_permission")
            )
    )
    @Builder.Default
    private Set<PermissionDetail> permissions = new LinkedHashSet<>();

    @Version
    private long version;
}
